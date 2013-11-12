package esg.security.registry.service.impl;

import java.io.File;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Date;
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
    private long fileLastReloaded = 0L; // Unix Epoch
    
    // mandatory reload time in seconds
    private int reloadEverySeconds = 600; // 10 minutes
    
    private static String DATE_FORMAT = "yyyy-MM-dd'T'HH:mm:ss.SSSZ";
    private static SimpleDateFormat df = new SimpleDateFormat(DATE_FORMAT);
    
    private final Log LOG = LogFactory.getLog(this.getClass());

    
    /**
     * Constructor accepts a list of comma-separated files.
     * Each file can be specified as an absolute file path (starting with '/') 
     * or as a relative classpath (not starting with '/').
     * Missing files are ignored, but a warning message is logged.
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
                File file = new File(filePath); 
                if (!file.exists()) {
                    LOG.warn("File "+file.getAbsolutePath()+" not found");
                    //throw new Exception("File "+file.getAbsolutePath()+" not found");
                } else {
                    files.add( file );
                }
            // classpath relative path
            } else {
                File file = new ClassPathResource(filePath).getFile();
                if (!file.exists()) {
                    LOG.warn("File "+file.getAbsolutePath()+" not found");
                    //throw new Exception("File "+file.getAbsolutePath()+" not found");
                } else {
                    files.add( file );
                }
            }
        }
    
    }
    
    public void setObserver(final ReloadableFileSetObserver observer) {
        this.observer = observer;
    }
    
    /**
     * Method that checks if any of the files has changed,
     * and notifies the observer in case it has.
     * A reload is forced even if the file hasn't changed,
     * but reloadEverySeconds has passed.
     */
    public void reload() {
        
        // loop over files
        for (final File file : files) {            
            if (file.exists() && 
                (file.lastModified()>fileLastReloaded || (fileLastReloaded+reloadEverySeconds*1000<System.currentTimeMillis()) )) {
                fileLastReloaded = System.currentTimeMillis();
                if (LOG.isInfoEnabled()) LOG.info("Reloading file set at time="+df.format(new Date(fileLastReloaded)));
                // notify the observer
                if (observer!=null) observer.parse(files);
                break;
            }
        }
        
    }

}
