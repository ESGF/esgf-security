package esg.node.security;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.util.Properties;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

public class ESGFProperties extends Properties {
    
    private final Log LOG = LogFactory.getLog(this.getClass());

    /**
     * 
     */
    private static final long serialVersionUID = 1L;
    
    public ESGFProperties() throws IOException, FileNotFoundException {

        // initialize empty Properties
        super();

        // load ESGF property values
        File propertyFile = new File( System.getenv().get("ESGF_HOME")+"/config/esgf.properties" );
        if (!propertyFile.exists()) propertyFile = new File("/esg/config/esgf.properties");
        this.load( new FileInputStream(propertyFile) );
        if (LOG.isInfoEnabled()) LOG.info("Loading properties from file: "+propertyFile.getAbsolutePath());

    }

}
