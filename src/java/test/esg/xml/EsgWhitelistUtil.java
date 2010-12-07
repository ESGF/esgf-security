package esg.xml;

import java.util.Iterator;
import java.util.List;

import java.io.FileInputStream;
import java.io.IOException;

import javax.xml.bind.JAXBContext;
import javax.xml.bind.JAXBException;
import javax.xml.bind.Unmarshaller;

import esg.xml.EsgWhitelist;
import esg.xml.EsgWhitelist.TrustedCAs;
import esg.xml.EsgWhitelist.TrustedCAs.PkiCA;
import esg.xml.EsgWhitelist.TrustedCAs.OpenIdCA;

import esg.xml.EsgWhitelist.TrustedServices;
import esg.xml.EsgWhitelist.TrustedServices.Gateway;
import esg.xml.EsgWhitelist.TrustedServices.Datanode;
import esg.xml.EsgWhitelist.TrustedServices.OpenIdIdentityProvider;

import esg.xml.EsgWhitelist.TrustedServices.Gateway.Myproxy;
import esg.xml.EsgWhitelist.TrustedServices.Gateway.AttributeService;
import esg.xml.EsgWhitelist.TrustedServices.Gateway.AuthorizationService;
import esg.xml.EsgWhitelist.TrustedServices.Gateway.OaiRepository;

public class EsgWhitelistUtil
{
    public static void printVersionDate(Integer versionDate)
    {
        String vstr = versionDate.toString();
        StringBuffer strbuf = new StringBuffer();
        strbuf.append(vstr.substring(4,6));
        strbuf.append("-");
        strbuf.append(vstr.substring(6,8));
        strbuf.append("-");
        strbuf.append(vstr.substring(0,4));
        System.out.println("Whitelist Version Date = " + strbuf);
    }

    public static void printOpenIdCAList(List<OpenIdCA> openIdCAs)
    {
        System.out.println("\n****************************** OpenID CA List ******************************");
        Iterator iter = openIdCAs.iterator(); 
        while(iter.hasNext())
        {
            OpenIdCA openIdCA = (OpenIdCA)iter.next(); 
            System.out.println("OpenId CA Hash = " + openIdCA.getHash() + ", DN = " + openIdCA.getDn());
        }
    }

    public static void printPkiCAList(List<PkiCA> pkicas)
    {
        System.out.println("\n******************************* PKI CA List *******************************");
        Iterator iter = pkicas.iterator(); 
        while(iter.hasNext())
        {
            PkiCA pkica = (PkiCA)iter.next(); 
            System.out.println("PKI CA Hash = " + pkica.getHash() + ", DN = " + pkica.getDn());
        }
    }

    public static void printOpenIdIdentityProviderList(List<OpenIdIdentityProvider> idps)
    {
        System.out.println("\n********************** OpenId Identity Provider List **********************");
        Iterator iter = idps.iterator();
        while(iter.hasNext())
        {
            OpenIdIdentityProvider idp = (OpenIdIdentityProvider)iter.next(); 
            System.out.println("IdentityProvider Org = " + idp.getOrganization() + ", URL = " + idp.getUrl());
        }
    }

    public static void printGatewayList(List<Gateway> gateways)
    {
        System.out.println("\n************************* Gateway Provider List **************************");
        Iterator iter = gateways.iterator();
        while(iter.hasNext())
        {
            Gateway gateway = (Gateway)iter.next(); 
            System.out.print("Gateway Org = " + gateway.getOrganization() + ", CommonName = " + gateway.getCommonName());
            System.out.println(", Hostname = " + gateway.getHostname() + ", id = " + gateway.getId());
            System.out.println("Description = " + gateway.getDescription());
            System.out.println("Base URL = " + gateway.getBaseUrl() + ", Secure Base URL = " + gateway.getBaseSecureUrl());
            System.out.println("Identity = " + gateway.getIdentity());
            System.out.println("Administrator Personal = " + gateway.getAdministratorPersonal() + ", Email = " + gateway.getAdministratorEmail());
            if (gateway.getAttributeService() != null)
            {
                AttributeService as = gateway.getAttributeService();
                if ((as.getUrl().length() > 0) || (as.getAuthorizationAuthority().length() > 0))
                {
                    System.out.println("    Attribute Service URL = " + as.getUrl());
                    System.out.println("    Attribute Service Authority = " + as.getAuthorizationAuthority());
                }
            }
            if (gateway.getAuthorizationService() != null)
            {
                AuthorizationService as = gateway.getAuthorizationService();
                if ((as.getUrl().length() > 0) || (as.getAuthorizationAuthority().length() > 0))
                {
                    System.out.println("    Authorization Service URL = " + as.getUrl());
                    System.out.println("    Authorization Service Authority = " + as.getAuthorizationAuthority());
                }
            }
            if (gateway.getOaiRepository() != null)
            {
                OaiRepository or = gateway.getOaiRepository();
                if ((or.getUrl().length() > 0) || (or.getAuthorizationAuthority().length() > 0))
                {
                    System.out.println("    OAI Repository Service URL = " + or.getUrl());
                    System.out.println("    OAI Repository Service Authority = " + or.getAuthorizationAuthority());
                }
            }
            if (gateway.getMyproxy() != null)
            {
                Myproxy mp = gateway.getMyproxy();
                System.out.println("    MyProxy Port = " + mp.getPort());
                System.out.println("    MyProxy Authority = " + mp.getAuthorizationAuthority());
            }
        }
    }

    public static void printDatanodeList(List<Datanode> datanodes)
    {
        System.out.println("\n************************* Datanode Provider List *************************");
        Iterator iter = datanodes.iterator();
        while(iter.hasNext())
        {
            Datanode datanode = (Datanode)iter.next(); 
            System.out.println("Datanode Org = " + datanode.getOrganization() + ", CommonName = " + datanode.getCommonName());
            if ((datanode.getThreddsURL() != null) && (datanode.getThreddsURL().length() > 0))
            {
                System.out.println("    Thredds URL = " + datanode.getThreddsURL());
            }
            if ((datanode.getGridftpURL() != null) && (datanode.getGridftpURL().length() > 0))
            {
                System.out.println("    Gridftp URL = " + datanode.getGridftpURL());
            }
        }
    }


    public static void main(String[] args)
    {
        try
        {
            JAXBContext jc = JAXBContext.newInstance("esg.xml");
            Unmarshaller u = jc.createUnmarshaller();
            EsgWhitelist ewl = (EsgWhitelist)u.unmarshal(
                new FileInputStream("EsgWhitelist.xml"));

            Integer versionDate = ewl.getVersionDate();
            printVersionDate(versionDate);

            TrustedCAs tcas = ewl.getTrustedCAs();

            List<PkiCA> pkicas = tcas.getPkiCA();
            printPkiCAList(pkicas);

            List<OpenIdCA> openIdCAs = tcas.getOpenIdCA();
            printOpenIdCAList(openIdCAs);

            TrustedServices tsvs = ewl.getTrustedServices();

            List<OpenIdIdentityProvider> idps = tsvs.getOpenIdIdentityProvider();
            printOpenIdIdentityProviderList(idps);
            
            List<Gateway> gateways = tsvs.getGateway();
            printGatewayList(gateways);

            List<Datanode> datanodes = tsvs.getDatanode();
            printDatanodeList(datanodes);
        }
        catch(Exception e)
        {
            e.printStackTrace();
        }
    }
}