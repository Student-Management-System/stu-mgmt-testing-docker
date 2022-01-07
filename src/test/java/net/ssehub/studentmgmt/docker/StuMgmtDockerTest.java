package net.ssehub.studentmgmt.docker;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.io.File;

import org.junit.jupiter.api.Test;

public class StuMgmtDockerTest {

    @Test
    public void constructorNotExistingDirectoryThrows() {
        IllegalArgumentException e = assertThrows(IllegalArgumentException.class, () -> new StuMgmtDocker(new File("doesnt_exist"), false));
        assertEquals("doesnt_exist is not a directory", e.getMessage());
    }
    
    @Test
    public void constructorDirectoryWithoutDockerComposeThrows() {
        File emptyDir = new File("empty");
        emptyDir.mkdir();
        
        try {
            IllegalArgumentException e = assertThrows(IllegalArgumentException.class, () -> new StuMgmtDocker(emptyDir, false));
            assertEquals("empty does not contain a docker-compose.yml file", e.getMessage());
        } finally {
            emptyDir.delete();
        }
    }
    
}
