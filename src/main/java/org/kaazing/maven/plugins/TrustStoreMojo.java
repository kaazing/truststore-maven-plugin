/**
 * Copyright 2007-2015, Kaazing Corporation. All rights reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.kaazing.maven.plugins;

import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.net.HttpURLConnection;
import java.net.URI;
import java.nio.charset.Charset;
import java.security.KeyStore;
import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateFactory;
import java.security.cert.CertificateNotYetValidException;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.apache.commons.codec.binary.Base64;
import org.apache.maven.plugin.AbstractMojo;
import org.apache.maven.plugin.MojoExecutionException;
import org.apache.maven.project.MavenProject;

/**
 * @goal generate-truststore
 * @phase generate-resources
 * @requiresDependencyResolution test
 */
public class TrustStoreMojo
    extends AbstractMojo {

    private static final Charset UTF8 = Charset.forName("UTF-8");

    // Max buffer size for a certificate: 8MB
    private static final int MAX_CERT_SIZE = (1024 * 1024 * 8);

    /* 
     * @parameter default-value="false" expression="${skipTests}"
     */
    private boolean skipTests;

    /**
     * @parameter expression="${project}"
     * @required
     * @readonly
     * @since 1.0
     */
    private MavenProject project = null;

    /**
     * @parameter default-value="src/main/gateway/conf/truststore.db" expression="${truststore.file}"
     */
    private String trustStoreFile;

    /**
     * @parameter default-value="JKS" expression="${truststore.type}"
     */
    private String trustStoreType;

    /**
     * @parameter default-value="changeit" expression="${truststore.pass}"
     */
    private String trustStorePass;

    /**
     * @parameter default-value="http://mxr.mozilla.org/mozilla-central/source/security/nss/lib/ckfw/builtins/certdata.txt?raw=1" expression="${truststore.source-url}"
     */
    private String trustStoreSourceURL;

    Map<String, String> getCertificates(String location)
        throws Exception {

        Map<String, String> certs = new HashMap<String, String>();

        Pattern labelPattern = Pattern.compile("^CKA_LABEL\\s+[A-Z0-9]+\\s+\\\"(.*)\\\"");
        Pattern beginContentPattern = Pattern.compile("^CKA_VALUE MULTILINE_OCTAL");
        Pattern endContentPattern = Pattern.compile("^END");
        Pattern untrustedPattern = Pattern.compile("^CKA_TRUST_SERVER_AUTH\\s+CK_TRUST\\s+CKT_NSS_NOT_TRUSTED$|^CKA_TRUST_SERVER_AUTH\\s+CK_TRUST\\s+CKT_NSS_TRUST_UNKNOWN$");

        URI certsURI = new URI(location);

        // This should be the default, but make sure it's set anyway
        HttpURLConnection.setFollowRedirects(true);

        HttpURLConnection conn = (HttpURLConnection) certsURI.toURL().openConnection();
        if (conn.getResponseCode() != HttpURLConnection.HTTP_OK) {
            throw new Exception(String.format("Error connecting to %s: %d %s", location, conn.getResponseCode(), conn.getResponseMessage()));
        }

        InputStream is = conn.getInputStream();
        InputStreamReader isr = new InputStreamReader(is);
        BufferedReader br = new BufferedReader(isr);

        String alias = null;
        byte[] certData = new byte[MAX_CERT_SIZE];
        int certDataLen = 0;

        String line = br.readLine();
        while (line != null) {
            // Skip comments and empty lines
            if (line.startsWith("#")) {
                line = br.readLine();
                continue;
            }

            if (line.trim().length() == 0) {
                line = br.readLine();
                continue;
            }

            Matcher m = labelPattern.matcher(line);
            if (m.find()) {
                alias = m.group(1).toLowerCase().replaceAll("/", "-").replaceAll("\\s+", "");
                line = br.readLine();
                continue;
            }

            m = beginContentPattern.matcher(line);
            if (m.find()) {
                line = br.readLine();

                while (true) {
                    m = endContentPattern.matcher(line);
                    if (m.find()) {
                        StringBuilder pem = new StringBuilder();
                        pem.append("-----BEGIN CERTIFICATE-----\n");

                        String base64Data = Base64.encodeBase64String(Arrays.copyOf(certData, certDataLen));
                        pem.append(base64Data);

                        pem.append("\n-----END CERTIFICATE-----\n");

                        certs.put(alias, pem.toString());

                        // Prepare for another certificate/trust section
                        alias = null;
                        certData = new byte[MAX_CERT_SIZE];
                        certDataLen = 0;

                        line = br.readLine();
                        break;
                    }

                    String[] octets = line.split("\\\\");

                    // We start at index 1, not zero, because the first element
                    // in the array will always be an empty string.  The first
                    // character in the string is a backslash; String.split()
                    // thus populates the element before that backslash as an
                    // empty string.
                    for (int i = 1; i < octets.length; i++) {
                        int octet = Integer.parseInt(octets[i], 8);
                        certData[certDataLen++] = (byte) octet;
                    }

                    line = br.readLine();
                }

                continue;
            }

            m = untrustedPattern.matcher(line);
            if (m.find()) {
                // Remove untrusted certs from our map
                certs.remove(alias);

                line = br.readLine();
                continue;
            }

            line = br.readLine();
        }

        return certs;
    }

    KeyStore getTrustStore(Map<String, String> certs,
                           String storeType)
        throws Exception {

        KeyStore ks = KeyStore.getInstance(storeType);

        // Initialize an empty keystore
        ks.load(null, null);

        CertificateFactory certFactory = CertificateFactory.getInstance("X.509");

        for (Map.Entry<String, String> elt : certs.entrySet()) {
            String alias = elt.getKey();

            try {
                ByteArrayInputStream bais = new ByteArrayInputStream(elt.getValue().getBytes(UTF8));

                X509Certificate cert = (X509Certificate) certFactory.generateCertificate(bais);
                cert.checkValidity();

                getLog().info(String.format("Adding certificate with alias '%s'", alias));
                ks.setCertificateEntry(alias, cert); 

            } catch (CertificateExpiredException cee) {
                getLog().error(String.format("NOT Adding certificate %s: %s", alias, cee));

            } catch (CertificateNotYetValidException cnyve) {
                getLog().error(String.format("NOT Adding certificate %s: %s", alias, cnyve));
            }
        }

        return ks;
    }

    KeyStore getTrustStore(Map<String, String> certs)
        throws Exception {

        return getTrustStore(certs, KeyStore.getDefaultType());
    }

    public void execute()
        throws MojoExecutionException {

        if (skipTests) {
            return;
        }

        String trustStoreTmpFile = String.format("%s%struststore.db",
            project.getBuild().getDirectory(), File.separator);

        getLog().info(String.format("TRUSTSTORE: truststore.file = '%s'", trustStoreFile));
        getLog().info(String.format("TRUSTSTORE: truststore.tmp-file = '%s'", trustStoreTmpFile));
        getLog().info(String.format("TRUSTSTORE: truststore.type = '%s'", trustStoreType));
        getLog().info(String.format("TRUSTSTORE: truststore.pass = '%s'", trustStorePass));
        getLog().info(String.format("TRUSTSTORE: truststore.source-url = '%s'", trustStoreSourceURL));

        File tmpFile = null;
        FileOutputStream fos = null;

        try {
            getLog().info(String.format("TRUSTSTORE: Generating new truststore.db from %s", trustStoreSourceURL));

            Map<String, String> certs = getCertificates(trustStoreSourceURL);
            KeyStore ks = getTrustStore(certs, trustStoreType);

            tmpFile = new File(trustStoreTmpFile);

            // make sure that the target directory exists:
            new File(tmpFile.getParent()).mkdirs();

            fos = new FileOutputStream(tmpFile);
            ks.store(fos, trustStorePass.toCharArray());

        } catch (Exception e) {
            getLog().error("TRUSTSTORE: Error while generating truststore: " + e.getMessage());
            throw new MojoExecutionException("Error while generating truststore: " + e.getMessage(), e);

        } finally {
            if (fos != null) {
                try {
                    fos.close();

                    File f = new File(trustStoreFile);

                    // Delete the destination file first; Windows will barf if
                    // you don't do that before trying to rename the original
                    // file to it.  This was the cause of KG-6456.

                    if (f.exists()) {
                      if (!f.isFile()) {
                          throw new MojoExecutionException(String.format("Error while generating truststore: truststore file '%s' already exists but is not a file", trustStoreFile));
                      }

                      if (!f.delete()) {
                          throw new MojoExecutionException(String.format("Error while generating truststore: truststore file '%s' already exists but could not be deleted", trustStoreFile));
                       }
                   }

                   if (!tmpFile.getCanonicalPath().equals(f.getCanonicalPath())) {
                       File parent = f.getParentFile();
                       if (!parent.exists()) {
                           if (!parent.mkdirs()) {
                               throw new IOException(String.format("Error creating directory '%s'", parent));
                           }
                       }

                       if (tmpFile.renameTo(f) == false) {
                           throw new IOException(String.format("Error renaming '%s' to '%s'", trustStoreTmpFile, trustStoreFile));
                       }
                   }

                   getLog().info(String.format("TRUSTSTORE: Renamed %s to %s", trustStoreTmpFile, trustStoreFile));

                } catch (IOException ioe) {
                    getLog().error("TRUSTSTORE: Error while generating truststore: " + ioe.getMessage());
                    throw new MojoExecutionException("Error while generating truststore: " + ioe.getMessage(), ioe);
                }
            }
        }
    }
}
