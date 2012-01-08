package esg.security.registry.service.impl;

import java.io.File;
import java.util.ArrayList;
import java.util.List;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.core.io.ClassPathResource;

import esg.security.registry.service.api.ReloadableFileSetObserver;

/**
 * Class that watches a set of local configuration files,
 * and notifies its observer when any of them has changed.
 * 
 * @author Luca Cinquini
 *
 */
public class ReloadableFileSet {
    
    // set of local files to watch
    private final List<File> files = new ArrayList<File>();
    
    // The object that needs to be notified when any of the files has changed.
    ReloadableFileSetObserver observer = null;
    
    // latest modification time of all files
    private long filesLastModTime = 0L; // Unix Epoch
    
    private final Log LOG = LogFactory.getLog(this.getClass());

    
    /**
     * Constructor accepts a list of comma-separated files.
     * Each file can be specified as an absolute file path (starting with '/') 
     * or as a relative classpath (not starting with '/').
     * 
     * @param xmlFilePath
     * @throws Exception
     */
    public ReloadableFileSet(final String filePaths) throws Exception {
        
        // loop over all configured local XML files
        for (final String filePath : filePaths.split("\\s*,\\s*")) {
            if (LOG.isInfoEnabled()) LOG.info("Using file:"+filePath);
            // absolute path
            if (filePath.startsWith("/")) {
                files.add( new File(filePath) );
            // classpath relative path
            } else {
                files.add( new ClassPathResource(filePath).getFile() );
            }
        }
    
    }
    
    public void setObserver(final ReloadableFileSetObserver observer) {
        this.observer = observer;
    }
    
    /**
     * Method that checks if any of the files has changed,
     * and notifies the observer in case it has.
     */
    public void reload() {
        
        // loop over files
        for (final File file : files) {
            if (file.exists() && file.lastModified()>filesLastModTime) {
                filesLastModTime = file.lastModified();
                if (LOG.isInfoEnabled()) LOG.info("File set has changed, reloading...");
                // notify the observer
                if (observer!=null) observer.parse(files);
                break;
            }
        }
        
    }

}
