package net.ssehub.studentmgmt.docker;



/**
 * Indicates a problem with running docker containers for testing purposes. An unchecked exception for convenience
 * in test code.
 * 
 * @author Adam
 */
public class DockerException extends RuntimeException {

    private static final long serialVersionUID = 697627935516955755L;

    /**
     * Creates an instance.
     */
    public DockerException() {
    }

    /**
     * Creates an instance.
     * 
     * @param message A message describing the exception.
     * @param cause The cause of this exception.
     */
    public DockerException(String message, Throwable cause) {
        super(message, cause);
    }

    /**
     * Creates an instance.
     * 
     * @param message A message describing the exception.
     */
    public DockerException(String message) {
        super(message);
    }

    /**
     * Creates an instance.
     * 
     * @param cause The cause of this exception.
     */
    public DockerException(Throwable cause) {
        super(cause);
    }
    
}
