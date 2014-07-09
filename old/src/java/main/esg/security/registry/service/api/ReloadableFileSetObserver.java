package esg.security.registry.service.api;

import java.io.File;
import java.util.List;

/**
 * Interface for an object that needs to be notified when one of a set of files has changed.
 * 
 * @author Luca Cinquini
 *
 */
public interface ReloadableFileSetObserver {
    
    void parse(List<File> files);

}
