// UserController.java
@RestController
@RequestMapping("/api/v1")
public class UserController {

    @Autowired
    private UserService userService;

    @GetMapping("/greet")
    public String greetUser(@RequestParam String username) {
        // SOURCE: 'username' is tainted.
        // It gets passed into a service method.
        return userService.formatGreeting(username);
    }
}

// UserService.java
@Service
public class UserService {
    
    public String formatGreeting(String input) {
        // Logic might be here, but the taint remains.
        // VULNERABLE SINK: Returning raw HTML with tainted data.
        // In a @RestController, the return string goes directly to the response body.
        return "<html><body><h1>Welcome, " + input + "!</h1></body></html>";
    }
}
