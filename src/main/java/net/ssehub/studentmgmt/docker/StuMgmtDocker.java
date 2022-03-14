package net.ssehub.studentmgmt.docker;


import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.lang.ProcessBuilder.Redirect;
import java.math.BigDecimal;
import java.net.ServerSocket;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;
import java.util.stream.Collectors;
import java.util.Properties;

import net.ssehub.studentmgmt.backend_api.api.AssignmentApi;
import net.ssehub.studentmgmt.backend_api.api.AuthenticationApi;
import net.ssehub.studentmgmt.backend_api.api.CourseApi;
import net.ssehub.studentmgmt.backend_api.api.CourseParticipantsApi;
import net.ssehub.studentmgmt.backend_api.api.DefaultApi;
import net.ssehub.studentmgmt.backend_api.api.GroupApi;
import net.ssehub.studentmgmt.backend_api.api.NotificationApi;
import net.ssehub.studentmgmt.backend_api.model.AssignmentDto;
import net.ssehub.studentmgmt.backend_api.model.AssignmentDto.CollaborationEnum;
import net.ssehub.studentmgmt.backend_api.model.AssignmentDto.StateEnum;
import net.ssehub.studentmgmt.backend_api.model.AssignmentDto.TypeEnum;
import net.ssehub.studentmgmt.backend_api.model.AssignmentUpdateDto;
import net.ssehub.studentmgmt.backend_api.model.ChangeCourseRoleDto;
import net.ssehub.studentmgmt.backend_api.model.ChangeCourseRoleDto.RoleEnum;
import net.ssehub.studentmgmt.backend_api.model.CourseConfigDto;
import net.ssehub.studentmgmt.backend_api.model.CourseCreateDto;
import net.ssehub.studentmgmt.backend_api.model.CourseDto;
import net.ssehub.studentmgmt.backend_api.model.GroupDto;
import net.ssehub.studentmgmt.backend_api.model.GroupSettingsDto;
import net.ssehub.studentmgmt.backend_api.model.PasswordDto;
import net.ssehub.studentmgmt.backend_api.model.SubmissionConfigDto;
import net.ssehub.studentmgmt.backend_api.model.SubscriberDto;
import net.ssehub.studentmgmt.sparkyservice_api.ApiClient;
import net.ssehub.studentmgmt.sparkyservice_api.ApiException;
import net.ssehub.studentmgmt.sparkyservice_api.api.AuthControllerApi;
import net.ssehub.studentmgmt.sparkyservice_api.api.RoutingControllerApi;
import net.ssehub.studentmgmt.sparkyservice_api.api.UserControllerApi;
import net.ssehub.studentmgmt.sparkyservice_api.model.AuthenticationInfoDto;
import net.ssehub.studentmgmt.sparkyservice_api.model.ChangePasswordDto;
import net.ssehub.studentmgmt.sparkyservice_api.model.CredentialsDto;
import net.ssehub.studentmgmt.sparkyservice_api.model.UserDto;
import net.ssehub.studentmgmt.sparkyservice_api.model.UsernameDto;
import net.ssehub.teaching.exercise_submitter.server.api.api.StatusApi;


/**
 * A utility class for integration tests that runs a fresh instance of the Student Management System in a Docker
 * container. Multiple instances can safely be used in parallel.
 * <p>
 * The purpose of this class is to ease testing; generally there are not many checks that the input data is valid. If
 * something fails, a {@link DockerException} is thrown. This generally only indicates that setting up a test case
 * failed; it does not allow for proper exception handling.
 * <p>
 * A number of public methods allow to create test data in the student management system. Additionally, getters allow
 * to get the API URLs of the different systems; these can be passed to the application that should be tested.
 * <p>
 * This class requires the content of
 * <a href="https://github.com/Student-Management-System/StuMgmtDocker">StuMgmtDocker</a>. It contains the Dockerfiles
 * and <code>docker-compose.yml</code> that are used to start the docker containers. The path to the root directory of
 * this repository (the one containing <code>docker-compose.yml</code>) needs to be passed to this class in either of
 * the following ways (higher entries take precedence over lower entries):
 * <ul>
 *  <li>As an argument to the constructor ({@link #StuMgmtDocker(File)})</li>
 *  <li>As the system property {@value #DOCKER_PROPERTY}</li>
 *  <li>In a file called {@value #DOCKER_LOCATION_FILE}; the first line of this file is used as the path</li>
 * </ul>
 * 
 * @author Adam
 * @author Lukas
 */
public class StuMgmtDocker implements AutoCloseable {

    private static final String DOCKER_PROPERTY = "net.ssehub.studentmgmt.docker.rootPath";
    
    private static final String DOCKER_LOCATION_FILE = "stu-mgmt-docker-rootPath.txt";
    
    private static final int WAITING_TIMEOUT_MS = 60000;
    
    private static final String EXERCISE_SUBMITTER_SERVER_USER = "exercise-submitter-server";
    
    private static final String EXERCISE_SUBMITTER_SERVER_PW = "asdfghjkl";
    
    private File dockerDirectory;
    
    private String dockerId;
    
    private int authPort;
    
    private int mgmtPort;
    
    private int submissionServerPort;

    private boolean withFrontend;
    
    private int webPort;
    
    private int pistonPort;
    
    private int webIdePort;
    
    private int showcasePort;
    
    private Map<String, String> userPasswords;
    
    private Map<String, String> userTokens;
    
    private Map<String, String> userMgmtIds;
    
    private Map<String, String> teachersOfCourse;
    
    /**
     * Starts a new instance of the Student Management System in docker containers. Waits until the services are fully
     * started.
     * 
     * @param dockerDirectory The directory where the <code>docker-compose.yml</code> file for the student management
     *      system lies.
     * @param withFrontend Whether to start the frontend (web) services, too.
     * 
     * @throws IllegalArgumentException If the given directory is not a directory or does not contain a
     *      docker-compose.yml file.
     * @throws DockerException If executing docker fails.
     */
    public StuMgmtDocker(File dockerDirectory, boolean withFrontend) throws DockerException {
        if (!dockerDirectory.isDirectory()) {
            throw new IllegalArgumentException(dockerDirectory + " is not a directory");
        }
        if (!new File(dockerDirectory, "docker-compose.yml").isFile()) {
            throw new IllegalArgumentException(dockerDirectory + " does not contain a docker-compose.yml file");
        }
        this.dockerDirectory = dockerDirectory;
        
        this.dockerId = String.format("stu-mgmt-testing-%04d", (int) (Math.random() * 10000));
        this.authPort = generateRandomPort();
        this.mgmtPort = generateRandomPort();
        this.submissionServerPort = generateRandomPort();
        
        this.withFrontend = withFrontend;
        if (withFrontend) {
            this.webPort = generateRandomPort();
            this.pistonPort = generateRandomPort();
            this.webIdePort = generateRandomPort();
            this.showcasePort = generateRandomPort();
        }
        
        try {
            startDocker();
            
            this.userPasswords = new HashMap<>();
            this.userPasswords.put("admin_user", "admin_pw");
            this.userTokens = new HashMap<>();
            
            this.userMgmtIds = new HashMap<>();
            this.teachersOfCourse = new HashMap<>();
            
            System.out.println("Waiting for services to be up...");
            waitUntilAuthReachable();
            waitUntilMgmtBackendReachable();
            
            createUser(EXERCISE_SUBMITTER_SERVER_USER, EXERCISE_SUBMITTER_SERVER_PW);
            waitUntilExerciseSubmitterServerReachable();
            
        } catch (DockerException e) {
            try {
                close();
            } catch (DockerException e1) {
                // ignore
            }
            throw e;
        }
    }
    
    /**
     * Starts a new instance of the Student Management System in docker containers. Does not start the frontend
     * services. Waits until the services are fully started.
     * 
     * @throws DockerException If executing docker fails.
     */
    public StuMgmtDocker() throws DockerException {
        this(getDockerRootPath(), false);
    }
    
    /**
     * Starts a new instance of the Student Management System in docker containers. Waits until the services are fully
     * started.
     * 
     * @param withFrontend Whether to start the frontend (web) services, too.
     * 
     * @throws DockerException If executing docker fails.
     */
    public StuMgmtDocker(boolean withFrontend) throws DockerException {
        this(getDockerRootPath(), withFrontend);
    }
    
    /**
     * Gets the path to the <code>docker-compose.yml</code> file from either the system property or the configuration
     * file.
     * 
     * @return The path to the docker root directory.
     * 
     * @throws DockerException If finding the directory fails.
     */
    private static File getDockerRootPath() throws DockerException {
        String configuredPath = System.getProperty(DOCKER_PROPERTY);
        if (configuredPath == null) {
            File configFile = new File(DOCKER_LOCATION_FILE);
            if (configFile.isFile()) {
                try (BufferedReader in = new BufferedReader(new FileReader(configFile))) {
                    configuredPath = in.readLine();
                } catch (IOException e) {
                    throw new DockerException("Failed to read " + DOCKER_LOCATION_FILE, e);
                }
            }
        }
        
        if (configuredPath == null) {
            throw new DockerException("Path to docker-compose.yml not configured; either set the " + DOCKER_PROPERTY
                    + " property or provide a file " + DOCKER_LOCATION_FILE + " in the current working directory");
        }
        
        return new File(configuredPath);
    }
    
    /**
     * Stops and removes the docker containers.
     * 
     * @throws DockerException If stopping the containers fails.
     */
    @Override
    public void close() throws DockerException {
        stopDocker();
    }
    
    /**
     * Generates a random ephemeral port number.
     *  
     * @return A random open port.
     */
    private int generateRandomPort() {
        int port;
        try (ServerSocket socket = new ServerSocket(0)) {
            socket.setReuseAddress(true);
            port = socket.getLocalPort();
            
        } catch (IOException e) {
            System.err.println("Failed to get free port: " + e.getMessage());
            System.err.println("Using random port number (might not be free)");
            port = (int) (Math.random() * (65535 - 49152)) + 49152;
        }
        
        return port;
    }
    
    /**
     * Helper method to start the docker containers.
     * 
     * @throws DockerException If starting the containers fails.
     */
    private void startDocker() throws DockerException {
        if (withFrontend) {
            runProcess("docker-compose", "--project-name", dockerId, "--profile", "frontend", "up", "--detach");
        } else {
            runProcess("docker-compose", "--project-name", dockerId, "up", "--detach");
        }
    }
    
    /**
     * Helper method to stop and remove the docker containers.
     * 
     * @throws DockerException If stopping the containers fails.
     */
    private void stopDocker() throws DockerException {
        runProcess("docker-compose", "--project-name", dockerId, "down", "--volumes");
    }
    
    /**
     * Runs a process in {@link #dockerDirectory} with the proper environment variables set.
     * 
     * @param command The command to run.
     * 
     * @throws DockerException If running the command fails.
     */
    private void runProcess(String... command) throws DockerException {
        ProcessBuilder pb = new ProcessBuilder(command);
        pb.directory(dockerDirectory);
        pb.inheritIO();
        pb.redirectErrorStream(true);
        pb.redirectOutput(Redirect.PIPE);
        
        Map<String, String> environment = pb.environment();
        setEnvironment(environment);
        
        Process p;
        try {
            p = pb.start();
        } catch (IOException e) {
            throw new DockerException("Failed to execute docker compose", e);
        }
        
        Thread outputReader = new Thread(() -> {
            try (BufferedReader processOuptutStream = new BufferedReader(new InputStreamReader(p.getInputStream()))) {
                
                String line;
                while ((line = processOuptutStream.readLine()) != null) {
                    System.out.println(line);
                }
                
            } catch (IOException e) {
                e.printStackTrace();
            }
        });
        outputReader.setDaemon(true);
        outputReader.start();
        
        boolean interrupted;
        do {
            try {
                int exitCode = p.waitFor();
                if (exitCode != 0) {
                    System.out.println("Warning: exit code for " + Arrays.toString(command) + " is " + exitCode);
                }
                interrupted = false;
                
            } catch (InterruptedException e) {
                interrupted = true;
            }
        } while (interrupted);
    }

    /**
     * Sets the required values in the environment.
     * 
     * @param environment The environment to set the variables in.
     * 
     * @throws DockerException If reading the args properties file fails.
     */
    private void setEnvironment(Map<String, String> environment) throws DockerException {
        Properties envArgs = new Properties();
        try (InputStream in = getClass().getResourceAsStream("/net/ssehub/studentmgmt/docker/args.properties")) {
            envArgs.load(in);
        } catch (IOException e) {
            throw new DockerException("Can't load properties file with environment arguments", e);
        }
        
        for (Entry<Object, Object> entry : envArgs.entrySet()) {
            environment.put(entry.getKey().toString(), entry.getValue().toString());
        }
        
        environment.put("FRONTEND_API_BASE_URL", getAuthUrl());
        environment.put("SPARKY_PORT", Integer.toString(authPort));
        environment.put("BACKEND_PORT", Integer.toString(mgmtPort));
        environment.put("SUBMISSION_SERVER_PORT", Integer.toString(submissionServerPort));
        environment.put("SUBMISSION_SERVER_MGMT_USER", EXERCISE_SUBMITTER_SERVER_USER);
        environment.put("SUBMISSION_SERVER_MGMT_PW", EXERCISE_SUBMITTER_SERVER_PW);
        if (withFrontend) {
            environment.put("FRONTEND_PORT", Integer.toString(webPort));
            environment.put("PISTON_PORT", Integer.toString(pistonPort));
            environment.put("WEB_IDE_PORT", Integer.toString(webIdePort));
            environment.put("SHOWCASE_PORT", Integer.toString(showcasePort));
            
            environment.put("SPARKY_SWAGGER_URL",
                    getAuthUrl() + "/swagger-ui/index.html?configUrl=/v3/api-docs/swagger-config");
            environment.put("BACKEND_SWAGGER_URL", getStuMgmtUrl() + "/api/");
            environment.put("FRONTEND_URL", getWebUrl());
            environment.put("SUBMISSION_SERVER_PATH", getExerciseSubmitterServerUrl());
            environment.put("WEB_IDE_URL", getWebIdeUrl());
            environment.put("WEB_IDE_CODE_EXECUTION_PATH", getPistonUrl());
        }
    }
    
    /**
     * Helper method that waits until the auth system (sparky-service) is alive (i.e. responds to heartbeat API).
     */
    private void waitUntilAuthReachable() {
        ApiClient client = new ApiClient();
        client.setBasePath(getAuthUrl());
        RoutingControllerApi api = new RoutingControllerApi(client);
        
        long tStart = System.currentTimeMillis();
        boolean success;
        do {
            try {
                api.isAlive();
                success = true;
            } catch (ApiException e) {
                success = false;
                try {
                    Thread.sleep(10);
                } catch (InterruptedException e1) {
                }
            }
        } while (!success && System.currentTimeMillis() - tStart < WAITING_TIMEOUT_MS);
        
        if (!success) {
            System.out.println("sparky-service not reachable for " + WAITING_TIMEOUT_MS + " ms");
        } else {
            System.out.println("sparky-service reachable (" + (System.currentTimeMillis() - tStart) + " ms)");
        }
    }
    
    /**
     * Helper method that waits until the mgmt backend is alive (i.e. responds to uptime API).
     */
    private void waitUntilMgmtBackendReachable() {
        net.ssehub.studentmgmt.backend_api.ApiClient client = new net.ssehub.studentmgmt.backend_api.ApiClient();
        client.setBasePath(getStuMgmtUrl());
        
        DefaultApi api = new DefaultApi(client);
        
        long tStart = System.currentTimeMillis();
        boolean success;
        do {
            try {
                api.appControllerGetUptime();
                success = true;
            } catch (net.ssehub.studentmgmt.backend_api.ApiException e) {
                success = false;
                try {
                    Thread.sleep(10);
                } catch (InterruptedException e1) {
                }
            }
        } while (!success && System.currentTimeMillis() - tStart < WAITING_TIMEOUT_MS);
        
        if (!success) {
            System.out.println("stu-mgmt-backend not reachable for " + WAITING_TIMEOUT_MS + " ms");
        } else {
            System.out.println("stu-mgmt-backend reachable (" + (System.currentTimeMillis() - tStart) + " ms)");
        }
    }
    
    /**
     * Helper method that waits until the exercise-submitter-server is alive (i.e. responds to heartbeat API).
     */
    private void waitUntilExerciseSubmitterServerReachable() {
        net.ssehub.teaching.exercise_submitter.server.api.ApiClient client
                = new net.ssehub.teaching.exercise_submitter.server.api.ApiClient();
        client.setBasePath(getExerciseSubmitterServerUrl());
        
        StatusApi api = new StatusApi(client);
        
        long tStart = System.currentTimeMillis();
        boolean success;
        do {
            try {
                api.heartbeat();
                success = true;
            } catch (net.ssehub.teaching.exercise_submitter.server.api.ApiException e) {
                success = false;
                try {
                    Thread.sleep(10);
                } catch (InterruptedException e1) {
                }
            }
        } while (!success && System.currentTimeMillis() - tStart < WAITING_TIMEOUT_MS);
        
        if (!success) {
            System.out.println("exercise-submitter-server not reachable for " + WAITING_TIMEOUT_MS + " ms");
        } else {
            System.out.println("exercise-submitter-server reachable ("
                    + (System.currentTimeMillis() - tStart) + " ms)");
        }
    }
    
    /**
     * Returns the URL for the Sparky-Service system.
     * 
     * @return The URL of the auth system
     */
    public String getAuthUrl() {
        return "http://localhost:" + authPort;
    }
    
    /**
     * Returns the URL of the Student Management System.
     * 
     * @return The stu-mgmt URL.
     */
    public String getStuMgmtUrl() {
        return "http://localhost:" + mgmtPort;
    }
    
    /**
     * Returns the URL to the exercise submission server.
     * 
     * @return The exercise submission server URL.
     */
    public String getExerciseSubmitterServerUrl() {
        return "http://localhost:" + submissionServerPort + "";
    }
    
    /**
     * Returns the ULR of the web client.
     * 
     * @return The web client URL.
     * 
     * @throws IllegalStateException If the frontend services were not started.
     */
    public String getWebUrl() throws IllegalStateException {
        if (!withFrontend) {
            throw new IllegalStateException();
        }
        return "http://localhost:" + webPort + "/";
    }
    
    /**
     * Returns the URL of the piston code execution service.
     * 
     * @return The URL to the piston service.
     * 
     * @throws IllegalStateException If the frontend services were not started.
     */
    public String getPistonUrl() throws IllegalStateException {
        if (!withFrontend) {
            throw new IllegalStateException();
        }
        return "http://localhost:" + pistonPort;
    }
    
    /**
     * Returns the URL of the web IDE client.
     * 
     * @return The URL to the web IDE client.
     * 
     * @throws IllegalStateException If the frontend services were not started.
     */
    public String getWebIdeUrl() throws IllegalStateException {
        if (!withFrontend) {
            throw new IllegalStateException();
        }
        return "http://localhost:" + webIdePort + "/";
    }
    
    /**
     * Returns the URL of the web showcase website.
     * 
     * @return The URL to the showcase.
     * 
     * @throws IllegalStateException If the frontend services were not started.
     */
    public String getShowcaseUrl() throws IllegalStateException {
        if (!withFrontend) {
            throw new IllegalStateException();
        }
        return "http://localhost:" + showcasePort + "/";
    }
    
    /**
     * Creates a user in the student management system.
     * 
     * @param name The username of the new user.
     * @param password The password of the new user.
     * 
     * @return The ID of the newly created user in the student management system (NOT in the auth system).
     * 
     * @throws DockerException If creating the user fails.
     */
    public String createUser(String name, String password) throws DockerException {
        if (password.length() < 6) {
            throw new IllegalArgumentException("Password must be at least 6 characters");
        }
        
        userPasswords.put(name, password);
        
        ApiClient client = getAuthenticatedAuthClient("admin_user");
        
        UserControllerApi api = new UserControllerApi(client);
        
        UserDto user;
        try {
            UsernameDto username = new UsernameDto();
            username.setUsername(name);
            
            user = api.createLocalUser(username);
        } catch (ApiException e) {
            System.err.println(e.getResponseBody());
            throw new DockerException(e);
        }
        
        try {
            ChangePasswordDto pwDto = new ChangePasswordDto();
            pwDto.setNewPassword(password);
            user.setPasswordDto(pwDto);
            
            api.editUser(user);
        } catch (ApiException e) {
            System.err.println(e.getResponseBody());
            throw new DockerException(e);
        }
        
        // make user "known" to stu-mgmt by calling its auth route
        net.ssehub.studentmgmt.backend_api.ApiClient backendClient = getAuthenticatedBackendClient(name);
        AuthenticationApi backendApi = new AuthenticationApi(backendClient);
        net.ssehub.studentmgmt.backend_api.model.UserDto dto;
        try {
            dto = backendApi.whoAmI();
            userMgmtIds.put(name, dto.getId());
            
        } catch (net.ssehub.studentmgmt.backend_api.ApiException e) {
            System.err.println(e.getResponseBody());
            throw new DockerException(e);
        }
        
        System.out.println("Created user " + name + " with password: " + password);
        return dto.getId();
    }
    
    /**
     * Helper method to get a token for user. Uses the cached password.
     * 
     * @param user The user to get the token for.
     * 
     * @return A valid token for the user.
     * 
     * @throws DockerException If getting the token fails.
     */
    public String getAuthToken(String user) throws DockerException {
        String token = userTokens.get(user);
        
        if (token == null) {
            ApiClient client = new ApiClient();
            client.setBasePath(getAuthUrl());
            
            CredentialsDto credentials = new CredentialsDto();
            credentials.setUsername(user);
            credentials.setPassword(userPasswords.get(user));
            
            AuthControllerApi api = new AuthControllerApi(client);
            AuthenticationInfoDto auth;
            try {
                auth = api.authenticate(credentials);
            } catch (ApiException e) {
                System.err.println(e.getResponseBody());
                throw new DockerException(e);
            }
            
            token = auth.getToken().getToken();
            userTokens.put(user, token);
        }
        
        return token;
    }
    
    /**
     * Helper method to get an authenticated client for the auth system (sparky-service) for a given user.
     * 
     * @param username The user to get the client for.
     * 
     * @return The authenticated client.
     * 
     * @throws DockerException If authenticating the client fails.
     */
    private ApiClient getAuthenticatedAuthClient(String username) throws DockerException {
        ApiClient client = new ApiClient();
        client.setBasePath(getAuthUrl());
        client.setAccessToken(getAuthToken(username));
        return client;
    }
    
    /**
     * Helper method to get an authenticated client for the stu-mgmt backend system for a given user.
     * 
     * @param username The user to get the client for.
     * 
     * @return The authenticated client.
     * 
     * @throws DockerException If authenticating the client fails.
     */
    private net.ssehub.studentmgmt.backend_api.ApiClient getAuthenticatedBackendClient(String username)
            throws DockerException {
        
        net.ssehub.studentmgmt.backend_api.ApiClient client = new net.ssehub.studentmgmt.backend_api.ApiClient();
        client.setBasePath(getStuMgmtUrl());
        client.setAccessToken(getAuthToken(username));
        return client;
    }
    
    /**
     * Creates a course in the student management system.
     * 
     * @param shortName The short name of the course.
     * @param semester The semester of the course, e.g. <code>wise2021</code>.
     * @param title The title of the course (human readable name).
     * @param lecturers The usernames that should be lecturers in this course.
     * 
     * @return The ID of the newly created course.
     * 
     * @throws DockerException If creating the course fails.
     */
    public String createCourse(String shortName, String semester, String title, String... lecturers)
            throws DockerException {
        
        if (!semester.matches("sose[0-9]{2}|wise[0-9]{4}")) {
            throw new IllegalArgumentException("Semester must match be in the form of sose21 or wise2122");
        }
        
        if (lecturers.length == 0) {
            throw new IllegalArgumentException("Course must have at least one lecturer");
        }
        
        net.ssehub.studentmgmt.backend_api.ApiClient client = getAuthenticatedBackendClient("admin_user");
        
        CourseApi courseApi = new CourseApi(client);
        
        GroupSettingsDto groupSettings = new GroupSettingsDto();
        groupSettings.setAllowGroups(true);
        groupSettings.setSelfmanaged(true);
        groupSettings.setAutoJoinGroupOnCourseJoined(false);
        groupSettings.setMergeGroupsOnAssignmentStarted(false);
        groupSettings.setSizeMin(BigDecimal.ZERO);
        groupSettings.setSizeMax(BigDecimal.TEN);
        
        CourseConfigDto courseConfig = new CourseConfigDto();
        courseConfig.setGroupSettings(groupSettings);
        
        CourseCreateDto courseCreate = new CourseCreateDto();
        courseCreate.setShortname(shortName);
        courseCreate.setSemester(semester);
        courseCreate.setTitle(title);
        courseCreate.setLecturers(Arrays.stream(lecturers).map(name -> name + "@LOCAL").collect(Collectors.toList()));
        courseCreate.setIsClosed(false);
        courseCreate.setConfig(courseConfig);
        
        String courseId;
        
        try {
            CourseDto dto = courseApi.createCourse(courseCreate);
            
            courseId = dto.getId();
            
        } catch (net.ssehub.studentmgmt.backend_api.ApiException e) {
            System.err.println(e.getResponseBody());
            throw new DockerException(e);
        }
        
        this.teachersOfCourse.put(courseId, lecturers[0]);
        
        System.out.println("Created course " + courseId + " (" + title + ")");
        return courseId;
    }
    
    /**
     * Enrolls a given user as a student in the given course.
     * 
     * @param courseId The ID of the course to enroll into.
     * @param student The username of the student to enrol.
     * 
     * @throws DockerException If enrolling the student fails.
     */
    public void enrollStudent(String courseId, String student) throws DockerException {
        net.ssehub.studentmgmt.backend_api.ApiClient client = getAuthenticatedBackendClient(student);
        CourseParticipantsApi api = new CourseParticipantsApi(client);
        
        try {
            PasswordDto pw = new PasswordDto();
            pw.setPassword("");
            
            api.addUser(pw, courseId, userMgmtIds.get(student));
        } catch (net.ssehub.studentmgmt.backend_api.ApiException e) {
            System.err.println(e.getResponseBody());
            throw new DockerException(e);
        }
        
        System.out.println("Enrolled " + student + " in course " + courseId);
    }
    
    /**
     * Creates a group of students in a given course.
     * 
     * @param courseId The ID of the course to create the group in.
     * @param groupName The name of the group.
     * @param members The usernames of the students to add to the group.
     * 
     * @return The ID of the created group.
     * 
     * @throws DockerException If creating the group fails.
     */
    public String createGroup(String courseId, String groupName, String... members) throws DockerException {
        net.ssehub.studentmgmt.backend_api.ApiClient client
                = getAuthenticatedBackendClient(teachersOfCourse.get(courseId));
        GroupApi api = new GroupApi(client);
        
        GroupDto group = new GroupDto();
        group.setName(groupName);
        
        try {
            group = api.createGroup(group, courseId);
        } catch (net.ssehub.studentmgmt.backend_api.ApiException e) {
            System.err.println(e.getResponseBody());
            throw new DockerException(e);
        }
        
        PasswordDto pw = new PasswordDto();
        pw.setPassword("");
        
        for (String member : members) {
            try {
                api.addUserToGroup(pw, courseId, group.getId(), userMgmtIds.get(member));
            } catch (net.ssehub.studentmgmt.backend_api.ApiException e) {
                System.err.println(e.getResponseBody());
                throw new DockerException(e);
            }
        }
        
        System.out.println("Created group " + groupName + " with members: " + Arrays.toString(members));
        
        return group.getId();
    }
    
    /**
     * The state of an assignment.
     */
    public enum AssignmentState {
        INVISIBLE(StateEnum.INVISIBLE,
                net.ssehub.studentmgmt.backend_api.model.AssignmentUpdateDto.StateEnum.INVISIBLE),
        CLOSED(StateEnum.CLOSED,
                net.ssehub.studentmgmt.backend_api.model.AssignmentUpdateDto.StateEnum.CLOSED),
        SUBMISSION(StateEnum.IN_PROGRESS,
                net.ssehub.studentmgmt.backend_api.model.AssignmentUpdateDto.StateEnum.IN_PROGRESS),
        IN_REVIEW(StateEnum.IN_REVIEW,
                net.ssehub.studentmgmt.backend_api.model.AssignmentUpdateDto.StateEnum.IN_REVIEW),
        REVIEWED(StateEnum.EVALUATED,
                net.ssehub.studentmgmt.backend_api.model.AssignmentUpdateDto.StateEnum.EVALUATED);
        
        private StateEnum createValue;
        
        private net.ssehub.studentmgmt.backend_api.model.AssignmentUpdateDto.StateEnum updateValue;

        /**
         * Creates an instance.
         * 
         * @param createValue The corresponding value for the backend-api library when creating an assignment.
         * @param updateValue The corresponding value for the backend-api library when updating an assignment.
         */
        private AssignmentState(StateEnum createValue,
                net.ssehub.studentmgmt.backend_api.model.AssignmentUpdateDto.StateEnum updateValue) {
            this.createValue = createValue;
            this.updateValue = updateValue;
        }
        
    }
    
    /**
     * The collboration type of an assignment.
     */
    public enum Collaboration {
        SINGLE(CollaborationEnum.SINGLE), GROUP(CollaborationEnum.GROUP);
        
        private CollaborationEnum apiValue;
        
        /**
         * Creates an instance.
         * 
         * @param apiValue The corresponding value for the backend-api library.
         */
        private Collaboration(CollaborationEnum apiValue) {
            this.apiValue = apiValue;
        }
        
    }
    
    /**
     * Creates an assignment in the given course.
     * <p>
     * Note that groups are only registered for an assignment in the {@link AssignmentState#SUBMISSION} state; if you
     * want to have groups registered in any other state, create it with state {@link AssignmentState#SUBMISSION} and
     * change to the desired state afterwards (see {@link #changeAssignmentState(String, String, AssignmentState)}).
     * <p>
     * If an SVN server is running for the given course, this method waits until the assignment is created in the SVN
     * repository.
     * 
     * @param courseId The course to create the assignment in.
     * @param name The name of the assignment.
     * @param state The state of the assignment.
     * @param collaboration The collaboration type of the assignment.
     * 
     * @return The ID of the assignment; used e.g. in {@link #changeAssignmentState(String, String, AssignmentState)}.
     * 
     * @throws DockerException If creating the assignment fails.
     */
    public String createAssignment(String courseId, String name, AssignmentState state,
            Collaboration collaboration) throws DockerException {
        
        net.ssehub.studentmgmt.backend_api.ApiClient client
                = getAuthenticatedBackendClient(teachersOfCourse.get(courseId));
        
        AssignmentApi assignmentApi = new AssignmentApi(client);
        
        AssignmentDto assignment = new AssignmentDto();
        assignment.setName(name);
        assignment.setState(state.createValue);
        assignment.setCollaboration(collaboration.apiValue);
        assignment.setType(TypeEnum.HOMEWORK);
        assignment.setPoints(BigDecimal.TEN);
        
        try {
            assignment = assignmentApi.createAssignment(assignment, courseId);
        } catch (net.ssehub.studentmgmt.backend_api.ApiException e) {
            System.err.println(e.getResponseBody());
            throw new DockerException(e);
        }
        
        System.out.println("Created " + collaboration.name() +  "-assignment " + name + " with status " + state.name());
        
        return assignment.getId();
    }
    
    /**
     * Changes the state of an assignment.
     * <p>
     * If an SVN server is running for the given course, this method waits until the assignment is created in the SVN
     * repository.
     * 
     * @param courseId The course where the assignment is in.
     * @param assignmentId The ID of the assignment, as returned by
     *      {@link #createAssignment(String, String, AssignmentState, Collaboration)}.
     * @param state The new state of the assignment.
     * 
     * @throws DockerException If changing the state fails.
     */
    public void changeAssignmentState(String courseId, String assignmentId, AssignmentState state)
            throws DockerException {
        
        net.ssehub.studentmgmt.backend_api.ApiClient client
                = getAuthenticatedBackendClient(teachersOfCourse.get(courseId));

        AssignmentApi assignmentApi = new AssignmentApi(client);
        
        AssignmentUpdateDto update = new AssignmentUpdateDto();
        update.setState(state.updateValue);
        
        AssignmentDto assignment;
        try {
            assignment = assignmentApi.updateAssignment(update, courseId, assignmentId);
        } catch (net.ssehub.studentmgmt.backend_api.ApiException e) {
            System.err.println(e.getResponseBody());
            throw new DockerException(e);
        }
        
        System.out.println("Changed assignment " + assignment.getName() + " to status " + state.name());
    }
    
    /**
     * Sets the tool configuration string for the given assignment and tool.
     * 
     * @param courseId The ID of the course that the assignment is in.
     * @param assignmentId The ID of the assignment to set the tool configuration string for.
     * @param tool The name (key) of the tool to set the string for.
     * @param configString The new configuration string to set.
     * 
     * @throws DockerException If getting the assignment or updating the configuration string fails.
     */
    public void setAssignmentToolConfigString(String courseId, String assignmentId, String tool, String configString)
            throws DockerException {
        
        net.ssehub.studentmgmt.backend_api.ApiClient client
                = getAuthenticatedBackendClient(teachersOfCourse.get(courseId));

        AssignmentApi assignmentApi = new AssignmentApi(client);
        
        try {
            AssignmentDto assignment = assignmentApi.getAssignmentById(courseId, assignmentId);
            List<SubmissionConfigDto> configs = assignment.getConfigs();
            if (configs == null) {
                configs = new LinkedList<>();
            }
            
            boolean found = false;
            for (SubmissionConfigDto config : configs) {
                if (config.getTool().equals(tool)) {
                    config.setConfig(configString);
                    found = true;
                    break;
                }
            }
            if (!found) {
                configs.add(new SubmissionConfigDto().tool(tool).config(configString));
            }
            
            AssignmentUpdateDto update = new AssignmentUpdateDto();
            update.setConfigs(configs);
            
            assignmentApi.updateAssignment(update, courseId, assignmentId);
            
        } catch (net.ssehub.studentmgmt.backend_api.ApiException e) {
            System.err.println(e.getResponseBody());
            throw new DockerException(e);
        }
    }

    /**
     * Sets up everything necessary that the exercise submission server can be used in the given course.
     * This including enrolling the user {@value #EXERCISE_SUBMITTER_SERVER_USER} as a lecturer and adding the server
     * as a subscriber to the notification API.
     * 
     * @param courseId The course to enable the exercise submitter server usage for.
     * 
     * @throws DockerException If enrolling the user as lecturer or adding the subscriber fails.
     */
    public void enableExerciseSubmissionServer(String courseId) throws DockerException {
        
        enrollStudent(courseId, EXERCISE_SUBMITTER_SERVER_USER);
        
        net.ssehub.studentmgmt.backend_api.ApiClient client
                = getAuthenticatedBackendClient(teachersOfCourse.get(courseId));
        
        CourseParticipantsApi participantsApi = new CourseParticipantsApi(client);
        
        try {
            participantsApi.updateUserRole(new ChangeCourseRoleDto().role(RoleEnum.LECTURER),
                    courseId, userMgmtIds.get("exercise-submitter-server"));
        } catch (net.ssehub.studentmgmt.backend_api.ApiException e) {
            System.err.println(e.getResponseBody());
            throw new DockerException(e);
        }
        
        NotificationApi api = new NotificationApi(client);
        
        SubscriberDto subscriber = new SubscriberDto();
        subscriber.setName("exercise-submission-server");
        subscriber.setUrl("http://exercise-submitter-server:8080/notify");
        subscriber.setEvents(Collections.singletonMap("ALL", true));
        
        try {
            api.subscribe(subscriber, courseId, subscriber.getName());
        } catch (net.ssehub.studentmgmt.backend_api.ApiException e) {
            System.err.println(e.getResponseBody());
            throw new DockerException(e);
        }
        
        System.out.println("Enrolled " + EXERCISE_SUBMITTER_SERVER_USER
                + " as teacher and enabled notifications for it in " + courseId);
    }
    
    /**
     * Runs an instance until enter is pressed in the console.
     * 
     * @param args Command line arguments; ignored.
     * 
     * @throws IOException If reading System.in fails.
     */
    public static void main(String[] args) throws IOException {
        final boolean withFrontend = true;
        
        try (StuMgmtDocker docker = new StuMgmtDocker(withFrontend)) {
            
            docker.createUser("adam", "123456");
            docker.createUser("student1", "123456");
            docker.createUser("student2", "123456");
            docker.createUser("student3", "123456");
            docker.createUser("student4", "123456");
            
            String courseId = docker.createCourse("java", "wise2021", "Programmierpraktikum: Java", "adam");
            docker.enableExerciseSubmissionServer(courseId);
            
            docker.enrollStudent(courseId, "student1");
            docker.enrollStudent(courseId, "student2");
            docker.enrollStudent(courseId, "student3");
            docker.enrollStudent(courseId, "student4");
            
            docker.createGroup(courseId, "JP001", "student1", "student3");
            docker.createGroup(courseId, "JP002", "student2", "student4");
            
            String a1 = docker.createAssignment(courseId, "Homework01", AssignmentState.INVISIBLE, Collaboration.GROUP);
            String a2 = docker.createAssignment(courseId, "Homework02", AssignmentState.INVISIBLE, Collaboration.GROUP);
            String t1 = docker.createAssignment(courseId, "Testat01", AssignmentState.INVISIBLE, Collaboration.SINGLE);
            
            docker.setAssignmentToolConfigString(courseId, a1, "exercise-submitter-checks",
                    "[{\"check\":\"encoding\",\"rejecting\":true},{\"check\":\"javac\"},"
                            + "{\"check\":\"checkstyle\",\"rules\":\"checkstyle.xml\"}]");
            docker.setAssignmentToolConfigString(courseId, a2, "exercise-submitter-checks",
                    "[{\"check\":\"encoding\",\"rejecting\":true},{\"check\":\"javac\"},"
                            + "{\"check\":\"checkstyle\",\"rules\":\"checkstyle.xml\"}]");
            docker.setAssignmentToolConfigString(courseId, t1, "exercise-submitter-checks",
                    "[{\"check\":\"encoding\",\"rejecting\":true},{\"check\":\"javac\"},"
                            + "{\"check\":\"checkstyle\",\"rules\":\"checkstyle.xml\"}]");
            
            docker.changeAssignmentState(courseId, a1, AssignmentState.SUBMISSION);
            docker.changeAssignmentState(courseId, a1, AssignmentState.IN_REVIEW);
            
            docker.changeAssignmentState(courseId, a2, AssignmentState.SUBMISSION);
            
            System.out.println();
            System.out.println();
            System.out.println("Docker running:");
            System.out.println("Auth:                " + docker.getAuthUrl());
            System.out.println("Mgmt:                " + docker.getStuMgmtUrl());
            System.out.println("Exercise Submission: " + docker.getExerciseSubmitterServerUrl());
            if (withFrontend) {
                System.out.println();
                System.out.println("Showcase:            " + docker.getShowcaseUrl());
                System.out.println("Stu-Mgmt Web:        " + docker.getWebUrl());
                System.out.println("Web-IDE:             " + docker.getWebIdeUrl());
                System.out.println("Piston:              " + docker.getPistonUrl());
            }
            
            System.out.println();
            System.out.println("Press enter to stop");
            
            System.in.read();
            
        } catch (DockerException e) {
            e.printStackTrace();
        }
    }
    
}
