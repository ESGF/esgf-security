package esg.security.attr.main;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.io.FileWriter;

import esg.security.attr.service.api.IdentityResolver;
import esg.security.attr.service.api.SAMLAttributes;
import esg.security.attr.service.impl.IdentityResolverImpl;
import esg.security.utils.ssl.CertUtils;


/**
 * Class that parses a file containing user openids (one per line)
 * and creates a file in the same directory containing comma-separated user personal information (one per line).
 * 
 * @author Luca Cinquini
 *
 */
public class IdentityResolverClient {

    /**
     * @param args
     */
    public static void main(String[] args) throws Exception {
        
        if (args.length!=1) {
            System.out.println("Usage: java esg.security.attr.main.IdentityResolverClient <path to openids file>" );
            System.exit(-1);
        }
        
        // instantiate identity resolver
        final IdentityResolver resolver = new IdentityResolverImpl();
                
        // set certificates for client-server handshake
        CertUtils.setTruststore("/Users/cinquini/myApplications/apache-tomcat/esg-truststore.ts");
        CertUtils.setKeystore("/Users/cinquini/myApplications/apache-tomcat/esg-datanode-rapidssl.ks");

        // input file
        File openids = new File(args[0]);
        BufferedReader reader = new BufferedReader(new FileReader(openids));
        
        // output file
        FileWriter writer = new FileWriter(openids.getParentFile().getAbsolutePath()+"/users.csv");

        String openid = null;
        while ((openid = reader.readLine()) != null) {
            try {
                //if (!openid.contains("pcmdi3")) {              
                    System.out.println("Resolving "+openid+"...");
                    SAMLAttributes attributes = resolver.resolve(openid.trim());
                    
                    System.out.println(openid+": "+attributes.getFirstName()+" "+attributes.getLastName()+" ("+attributes.getEmail()+")");
                    writer.write(openid.trim()+","+attributes.getFirstName()+" "+attributes.getLastName()+","+attributes.getEmail()+"\n");
                //}
            } catch(Exception e) {
                // keep resolving other openids
                System.out.println(e.getMessage());
            }
        }

        reader.close();
        writer.close();
 

    }

}
