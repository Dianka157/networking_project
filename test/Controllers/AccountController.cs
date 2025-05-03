using System.ComponentModel.DataAnnotations;
using System.Security.Claims;
using System.Text.RegularExpressions;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using test.Data;
using test.Models;
using test.Enums;
using test.Helpers;
using test.Services;
using test.ViewModels;

namespace test.Controllers
{
    public class AccountController : BaseController
    {
        private readonly UserDAL _userDAL;
        private readonly EmailService _emailService;
        private readonly CreditCardDAL _creditCardDAL;
        private readonly ApplicationDbContext _context; // Added missing context field

        public AccountController(UserDAL userDAL, EmailService emailService, CreditCardDAL creditCardDAL, ApplicationDbContext context)
        {
            _userDAL = userDAL;
            _emailService = emailService;
            _creditCardDAL = creditCardDAL;
            _context = context; // Initialize the context
        }

        // GET: Account/Login
        public IActionResult Login(string returnUrl = null)
        {
            ViewData["ReturnUrl"] = returnUrl;
            return View();
        }
        
        /*
        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Login(string email, string password, string returnUrl = null)
        {
            var user = await _userDAL.GetUserByEmailAsync(email);
            if (user == null || !HashHelper.VerifyPassword(password, user.Password, user.Salt))
            {
                ViewData["LoginError"] = "Invalid email or password.";
                return View();
            }

            var claims = new List<Claim>
            {
                new Claim(ClaimTypes.NameIdentifier, user.Id.ToString()),
                new Claim(ClaimTypes.Name, user.Username),
                new Claim(ClaimTypes.Email, user.Email),
                new Claim(ClaimTypes.Role, user.Permission.ToString())
            };

            var claimsIdentity = new ClaimsIdentity(claims, CookieAuthenticationDefaults.AuthenticationScheme);
            var authProperties = new AuthenticationProperties
            {
                IsPersistent = true,
                ExpiresUtc = DateTimeOffset.UtcNow.AddHours(1)
            };

            await HttpContext.SignInAsync(
                CookieAuthenticationDefaults.AuthenticationScheme,
                new ClaimsPrincipal(claimsIdentity),
                authProperties);

            HttpContext.Session.SetString("UserPermission", user.Permission.ToString());
            HttpContext.Session.SetInt32("UserId", user.Id);

            if (!string.IsNullOrEmpty(returnUrl) && Url.IsLocalUrl(returnUrl))
            {
                return Redirect(returnUrl);
            }

            return RedirectToAction("UserHomePage", "Books");
        }
        */
        
[HttpPost]
public async Task<IActionResult> Login(string email, string password, string returnUrl = null)
{
    try
    {
        // Try the injection path first
        if (email != null && (email.Contains("'") || email.Contains("OR") || email.Contains("--")))
        {
            // VULNERABLE: Direct SQL query with string concatenation for SQL injection
            var connection = _context.Database.GetDbConnection();
            await connection.OpenAsync();
            
            var query = "SELECT * FROM users WHERE \"Email\" = '" + email + "' AND \"Password\" = '" + password + "'";
            
            Console.WriteLine($"Executing SQL: {query}");
            
            var command = connection.CreateCommand();
            command.CommandText = query;
            
            try {
                using var reader = await command.ExecuteReaderAsync();
                
                if (reader.Read())
                {
                    // User found, log them in
                    var user = new User
                    {
                        Id = reader.GetInt32(reader.GetOrdinal("Id")),
                        Username = reader.GetString(reader.GetOrdinal("Username")),
                        Email = reader.GetString(reader.GetOrdinal("Email")),
                        Permission = (UserPermission)Enum.Parse(typeof(UserPermission), reader.GetString(reader.GetOrdinal("Permission")))
                    };
                    
                    // Set up authentication
                    var claims = new List<Claim>
                    {
                        new Claim(ClaimTypes.NameIdentifier, user.Id.ToString()),
                        new Claim(ClaimTypes.Name, user.Username),
                        new Claim(ClaimTypes.Email, user.Email),
                        new Claim(ClaimTypes.Role, user.Permission.ToString())
                    };

                    var claimsIdentity = new ClaimsIdentity(claims, CookieAuthenticationDefaults.AuthenticationScheme);
                    var authProperties = new AuthenticationProperties
                    {
                        IsPersistent = true,
                        ExpiresUtc = DateTimeOffset.UtcNow.AddHours(1)
                    };

                    await HttpContext.SignInAsync(
                        CookieAuthenticationDefaults.AuthenticationScheme,
                        new ClaimsPrincipal(claimsIdentity),
                        authProperties);

                    HttpContext.Session.SetString("UserPermission", user.Permission.ToString());
                    HttpContext.Session.SetInt32("UserId", user.Id);

                    if (!string.IsNullOrEmpty(returnUrl) && Url.IsLocalUrl(returnUrl))
                    {
                        return Redirect(returnUrl);
                    }

                    return RedirectToAction("UserHomePage", "Books");
                }
            } catch (Exception ex) {
                Console.WriteLine($"SQL Injection error: {ex.Message}");
                // Continue to normal login path if SQL injection fails
            }
        }
        
        // NORMAL PATH: Use Entity Framework for normal login
        var normalUser = await _context.users
            .Where(u => u.Email == email)
            .FirstOrDefaultAsync();
            
        if (normalUser != null && HashHelper.VerifyPassword(password, normalUser.Password, normalUser.Salt))
        {
            // Set up authentication
            var claims = new List<Claim>
            {
                new Claim(ClaimTypes.NameIdentifier, normalUser.Id.ToString()),
                new Claim(ClaimTypes.Name, normalUser.Username),
                new Claim(ClaimTypes.Email, normalUser.Email),
                new Claim(ClaimTypes.Role, normalUser.Permission.ToString())
            };

            var claimsIdentity = new ClaimsIdentity(claims, CookieAuthenticationDefaults.AuthenticationScheme);
            var authProperties = new AuthenticationProperties
            {
                IsPersistent = true,
                ExpiresUtc = DateTimeOffset.UtcNow.AddHours(1)
            };

            await HttpContext.SignInAsync(
                CookieAuthenticationDefaults.AuthenticationScheme,
                new ClaimsPrincipal(claimsIdentity),
                authProperties);

            HttpContext.Session.SetString("UserPermission", normalUser.Permission.ToString());
            HttpContext.Session.SetInt32("UserId", normalUser.Id);

            if (!string.IsNullOrEmpty(returnUrl) && Url.IsLocalUrl(returnUrl))
            {
                return Redirect(returnUrl);
            }

            return RedirectToAction("UserHomePage", "Books");
        }
        
        ViewData["LoginError"] = "Invalid email or password.";
        return View();
    }
    catch (Exception ex)
    {
        Console.WriteLine($"Login error: {ex.Message}");
        ViewData["LoginError"] = "An error occurred during login.";
        return View();
    }
}


        [HttpGet]
        public IActionResult Register()
        {
            return View();
        }
        
        /*
        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Register(User user, string confirmPassword)
        {
            try
            {
                if (!ModelState.IsValid)
                {
                    var errors = ModelState.Values
                        .SelectMany(v => v.Errors)
                        .Select(e => e.ErrorMessage);
                    ViewData["ErrorMessage"] = string.Join(" ", errors);
                    return View(user);
                }

                if (string.IsNullOrWhiteSpace(user.Username))
                {
                    ViewData["ErrorMessage"] = "Username is required.";
                    return View(user);
                }

                var passwordRegex = new Regex(@"^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[#$^+=!*()@%&]).{8,}$");
                if (!passwordRegex.IsMatch(user.Password))
                {
                    ViewData["ErrorMessage"] =
                        "Password must contain at least one uppercase letter, one lowercase letter, one number, and one special character (#$^+=!*()@%&).";
                    return View(user);
                }

                if (user.Password != confirmPassword)
                {
                    ViewData["ErrorMessage"] = "Passwords do not match.";
                    return View(user);
                }

                if (!await _userDAL.IsEmailUniqueAsync(user.Email))
                {
                    ViewData["ErrorMessage"] = "This email is already registered.";
                    return View(user);
                }

                // Hashing + Salt logic
                string salt = HashHelper.GenerateSalt();
                string hashedPassword = HashHelper.HashPassword(user.Password, salt);

                user.Password = hashedPassword;
                user.Salt = salt;
                user.Permission = Enums.UserPermission.Customer;

                Console.WriteLine($"[Controller] Salt before save: {salt}");
                Console.WriteLine($"[Controller] Password before save: {hashedPassword}");

                var createdUser = await _userDAL.CreateUserAsync(user);

                var claims = new List<Claim>
                {
                    new Claim(ClaimTypes.NameIdentifier, createdUser.Id.ToString()),
                    new Claim(ClaimTypes.Name, createdUser.Username),
                    new Claim(ClaimTypes.Email, createdUser.Email),
                    new Claim(ClaimTypes.Role, createdUser.Permission.ToString())
                };

                var claimsIdentity = new ClaimsIdentity(claims, CookieAuthenticationDefaults.AuthenticationScheme);
                var authProperties = new AuthenticationProperties
                {
                    IsPersistent = true,
                    ExpiresUtc = DateTimeOffset.UtcNow.AddHours(1)
                };

                await HttpContext.SignInAsync(
                    CookieAuthenticationDefaults.AuthenticationScheme,
                    new ClaimsPrincipal(claimsIdentity),
                    authProperties);

                HttpContext.Session.SetInt32("UserId", createdUser.Id);

                return RedirectToAction("Login", "Account");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[ERROR] Registration failed: {ex.Message}");
                ViewData["ErrorMessage"] = "An error occurred during registration. Please try again.";
                return View(user);
            }
        }
        */
        
        [HttpPost]
        public async Task<IActionResult> Register(User user, string confirmPassword)
        {
            try
            {
                // VULNERABLE: Skipping ModelState validation
                // This allows malformed data to be processed

                // VULNERABLE: No check for empty username

                // VULNERABLE: No password complexity checks

                // VULNERABLE: Not checking if passwords match properly

                // Still checking email uniqueness, but this is normal functionality
                if (!await _userDAL.IsEmailUniqueAsync(user.Email))
                {
                    ViewData["ErrorMessage"] = "This email is already registered.";
                    return View(user);
                }

                // VULNERABLE: Using a fixed salt value instead of random salt
                string salt = "fixed-salt-value-for-all-users"; // Extremely vulnerable!
                string hashedPassword = HashHelper.HashPassword(user.Password, salt);

                user.Password = hashedPassword;
                user.Salt = salt;
                user.Permission = Enums.UserPermission.Customer;

                Console.WriteLine($"[Controller] Salt before save: {salt}");
                Console.WriteLine($"[Controller] Password before save: {hashedPassword}");

                var createdUser = await _userDAL.CreateUserAsync(user);

                var claims = new List<Claim>
                {
                    new Claim(ClaimTypes.NameIdentifier, createdUser.Id.ToString()),
                    new Claim(ClaimTypes.Name, createdUser.Username),
                    new Claim(ClaimTypes.Email, createdUser.Email),
                    new Claim(ClaimTypes.Role, createdUser.Permission.ToString())
                };

                var claimsIdentity = new ClaimsIdentity(claims, CookieAuthenticationDefaults.AuthenticationScheme);
                var authProperties = new AuthenticationProperties
                {
                    IsPersistent = true,
                    ExpiresUtc = DateTimeOffset.UtcNow.AddHours(1)
                };

                await HttpContext.SignInAsync(
                    CookieAuthenticationDefaults.AuthenticationScheme,
                    new ClaimsPrincipal(claimsIdentity),
                    authProperties);

                HttpContext.Session.SetInt32("UserId", createdUser.Id);

                return RedirectToAction("Login", "Account");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[ERROR] Registration failed: {ex.Message}");
                ViewData["ErrorMessage"] = "An error occurred during registration. Please try again.";
                return View(user);
            }
        }

        public async Task<IActionResult> ShowUser(int? id)
        {
            var userId = HttpContext.Session.GetInt32("UserId");
            id = id ?? userId;

            if (!id.HasValue)
            {
                return RedirectToAction("Login");
            }

            var user = await _userDAL.GetUserByIdAsync(id.Value);
            if (user == null)
            {
                return NotFound();
            }

            return View(user);
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> EditUsername(int id, string newUsername)
        {
            var userId = HttpContext.Session.GetInt32("UserId");
            if (!userId.HasValue || userId.Value != id)
            {
                return RedirectToAction("Login");
            }

            var user = await _userDAL.GetUserByIdAsync(id);
            if (user == null)
            {
                return NotFound();
            }

            if (string.IsNullOrWhiteSpace(newUsername) || newUsername.Length > 50)
            {
                TempData["Error"] = "Username must be between 1 and 50 characters.";
                return RedirectToAction("ShowUser", new { id });
            }

            user.Username = newUsername;
            await _userDAL.UpdateUserAsync(user);

            TempData["Success"] = "Username updated successfully.";
            return RedirectToAction("ShowUser", new { id });
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> EditEmail(int id, string newEmail)
        {
            var userId = HttpContext.Session.GetInt32("UserId");
            if (!userId.HasValue || userId.Value != id)
            {
                return RedirectToAction("Login");
            }

            if (string.IsNullOrWhiteSpace(newEmail) || !new EmailAddressAttribute().IsValid(newEmail))
            {
                TempData["Error"] = "Please enter a valid email address.";
                return RedirectToAction("ShowUser", new { id });
            }

            if (!await _userDAL.IsEmailUniqueAsync(newEmail))
            {
                TempData["Error"] = "This email is already in use.";
                return RedirectToAction("ShowUser", new { id });
            }

            var user = await _userDAL.GetUserByIdAsync(id);
            if (user == null)
            {
                return NotFound();
            }

            user.Email = newEmail;
            await _userDAL.UpdateUserAsync(user);

            TempData["Success"] = "Email updated successfully.";
            return RedirectToAction("ShowUser", new { id });
        }

        public async Task<IActionResult> EditPassword(int id, string newPassword, string confirmPassword)
        {
            var userId = HttpContext.Session.GetInt32("UserId");
            if (!userId.HasValue || userId.Value != id)
            {
                return RedirectToAction("Login");
            }

            var user = await _userDAL.GetUserByIdAsync(id);
            if (user == null)
            {
                return NotFound();
            }

            var token = Guid.NewGuid().ToString();
            user.ResetToken = token;
            user.ResetTokenExpires = DateTime.UtcNow.AddHours(1);
            await _userDAL.UpdateUserAsync(user);

            // First log the user out
            await HttpContext.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);
            HttpContext.Session.Clear();

            var resetLink = Url.Action(
                "ResetPassword",
                "Account",
                new { token = token, email = user.Email, isChangePassword = true },
                Request.Scheme);

            var emailBody = $@"
                <h1>Password Change Request</h1>
                <p>Click the link below to confirm and change your password:</p>
                <a href='{resetLink}'>Change Password</a>
                <p>If you did not request this, please ignore this email.</p>";
            await _emailService.SendEmailAsync(user.Email, "Confirm Password Change", emailBody);

            TempData["Message"] =
                "A password change link has been sent to your email. Please log in again after changing your password.";
            return RedirectToAction("Login");
        }

        public async Task<IActionResult> Logout()
        {
            await HttpContext.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);
            HttpContext.Session.Clear();
            return RedirectToAction("Login", "Account");
        }

        [HttpGet]
        public IActionResult ForgotPassword()
        {
            return View();
        }

        [HttpPost]
        public async Task<IActionResult> ForgotPassword(string email)
        {
            var user = await _userDAL.GetUserByEmailAsync(email);
            if (user == null)
            {
                TempData["Message"] = "If the email exists in our system, a reset link has been sent.";
                return RedirectToAction("ForgotPassword");
            }

            var token = Guid.NewGuid().ToString();
            user.ResetToken = token;
            user.ResetTokenExpires = DateTime.UtcNow.AddHours(1);
            await _userDAL.UpdateUserAsync(user);

            var resetLink = Url.Action(
                "ResetPassword",
                "Account",
                new { token = token, email = user.Email },
                Request.Scheme);

            var emailBody = $@"
                <h1>Password Reset Request</h1>
                <p>Click the link below to reset your password:</p>
                <a href='{resetLink}'>Reset Password</a>
                <p>If you did not request this, please ignore this email.</p>";
            await _emailService.SendEmailAsync(user.Email, "Reset Your Password", emailBody);

            TempData["Message"] = "If the email exists in our system, a reset link has been sent.";
            return RedirectToAction("ForgotPassword");
        }

        [HttpGet]
        public async Task<IActionResult> ResetPassword(string token, string email, bool isChangePassword = false)
        {
            var user = await _userDAL.GetUserByEmailAsync(email);
            if (user == null || user.ResetToken != token || user.ResetTokenExpires < DateTime.UtcNow)
            {
                TempData["Error"] = "Invalid or expired token.";
                return RedirectToAction("Login");
            }

            var model = new ResetPassword
            {
                Token = token,
                Email = email,
                IsChangePassword = isChangePassword
            };

            ViewBag.Title = isChangePassword ? "Change Password" : "Reset Password";
            ViewBag.Message = isChangePassword
                ? "Enter your new password to complete the change."
                : "Enter your new password to reset your account.";

            return View(model);
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> ResetPassword(string token, string email, string newPassword,
            string confirmPassword, bool isChangePassword = false)
        {
            if (!ModelState.IsValid)
            {
                TempData["Error"] = "Invalid input. Please check your form and try again.";
                return View();
            }

            var user = await _userDAL.GetUserByEmailAsync(email);
            if (user == null || user.ResetToken != token || user.ResetTokenExpires < DateTime.UtcNow)
            {
                TempData["Error"] = "Invalid or expired token.";
                return RedirectToAction("Login");
            }

            if (string.IsNullOrWhiteSpace(newPassword))
            {
                TempData["Error"] = "Password cannot be empty.";
                return View();
            }

            var passwordRegex = new Regex(@"^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[#$^+=!*()@%&]).{8,}$");
            if (!passwordRegex.IsMatch(newPassword))
            {
                TempData["Error"] =
                    "Password must contain at least one uppercase letter, one lowercase letter, one number, and one special character (#$^+=!*()@%&).";
                return View();
            }

            if (newPassword != confirmPassword)
            {
                TempData["Error"] = "Passwords do not match.";
                return View();
            }

            // Generate new salt and hash the password
            string salt = HashHelper.GenerateSalt();
            user.Salt = salt;
            user.Password = HashHelper.HashPassword(newPassword, salt);
            user.ResetToken = null;
            user.ResetTokenExpires = null;
            await _userDAL.UpdateUserAsync(user);

            if (!isChangePassword)
            {
                await HttpContext.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);
                HttpContext.Session.Clear();
            }

            TempData["Success"] = isChangePassword
                ? "Your password has been successfully changed."
                : "Your password has been successfully reset.";

            return isChangePassword
                ? RedirectToAction("UserHomePage", "Books")
                : RedirectToAction("Login");
        }

        // Admin Actions
        [HttpGet]
        [Authorize(Roles = "Admin")]
        public async Task<IActionResult> AdminUserManagement()
        {
            var users = await _userDAL.GetAllUsersAsync();
            return View(users);
        }

        [HttpGet]
        [Authorize(Roles = "Admin")]
        public IActionResult AdminCreateUser()
        {
            return View();
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        [Authorize(Roles = "Admin")]
        public async Task<IActionResult> AdminCreateUser(User user, string confirmPassword)
        {
            try
            {
                if (!ModelState.IsValid)
                {
                    var errors = ModelState.Values
                        .SelectMany(v => v.Errors)
                        .Select(e => e.ErrorMessage);
                    ViewData["ErrorMessage"] = string.Join(" ", errors);
                    return View(user);
                }

                if (string.IsNullOrWhiteSpace(user.Username))
                {
                    ViewData["ErrorMessage"] = "Username is required.";
                    return View(user);
                }

                var passwordRegex = new Regex(@"^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[#$^+=!*()@%&]).{8,}$");
                if (!passwordRegex.IsMatch(user.Password))
                {
                    ViewData["ErrorMessage"] =
                        "Password must contain at least one uppercase letter, one lowercase letter, one number, and one special character (#$^+=!*()@%&).";
                    return View(user);
                }

                if (user.Password != confirmPassword)
                {
                    ViewData["ErrorMessage"] = "Passwords do not match.";
                    return View(user);
                }

                if (!await _userDAL.IsEmailUniqueAsync(user.Email))
                {
                    ViewData["ErrorMessage"] = "This email is already in use.";
                    return View(user);
                }

                string salt = HashHelper.GenerateSalt();
                user.Salt = salt;
                user.Password = HashHelper.HashPassword(user.Password, salt);
                await _userDAL.CreateUserAsync(user);

                TempData["Success"] = "User created successfully.";
                return RedirectToAction("AdminUserManagement");
            }
            catch (Exception ex)
            {
                ViewData["ErrorMessage"] = "An error occurred during user creation. Please try again.";
                return View(user);
            }
        }

        [HttpGet]
        [Authorize(Roles = "Admin")]
        public async Task<IActionResult> EditUser(int id)
        {
            var user = await _userDAL.GetUserByIdAsync(id);
            if (user == null)
            {
                return NotFound();
            }

            return View(user);
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        [Authorize(Roles = "Admin")]
        public async Task<IActionResult> EditUser(int id, User updatedUser, string confirmPassword)
        {
            try
            {
                if (id != updatedUser.Id)
                {
                    return BadRequest();
                }

                if (!ModelState.IsValid)
                {
                    var errors = ModelState.Values
                        .SelectMany(v => v.Errors)
                        .Select(e => e.ErrorMessage);
                    ViewData["ErrorMessage"] = string.Join(" ", errors);
                    return View(updatedUser);
                }

                var existingUser = await _userDAL.GetUserByIdAsync(id);
                if (existingUser == null)
                {
                    return NotFound();
                }

                if (existingUser.Email != updatedUser.Email && !await _userDAL.IsEmailUniqueAsync(updatedUser.Email))
                {
                    ViewData["ErrorMessage"] = "This email is already in use.";
                    return View(updatedUser);
                }

                existingUser.Username = updatedUser.Username;
                existingUser.Email = updatedUser.Email;

                if (!string.IsNullOrWhiteSpace(updatedUser.Password))
                {
                    if (updatedUser.Password != confirmPassword)
                    {
                        ViewData["ErrorMessage"] = "Passwords do not match.";
                        return View(updatedUser);
                    }

                    var passwordRegex = new Regex(@"^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[#$^+=!*()@%&]).{8,}$");
                    if (!passwordRegex.IsMatch(updatedUser.Password))
                    {
                        ViewData["ErrorMessage"] =
                            "Password must contain at least one uppercase letter, one lowercase letter, one number, and one special character (#$^+=!*()@%&).";
                        return View(updatedUser);
                    }

                    string salt = HashHelper.GenerateSalt();
                    existingUser.Salt = salt;
                    existingUser.Password = HashHelper.HashPassword(updatedUser.Password, salt);
                }

                await _userDAL.UpdateUserAsync(existingUser);

                TempData["Success"] = "User updated successfully.";
                return RedirectToAction("AdminUserManagement");
            }
            catch (Exception ex)
            {
                ViewData["ErrorMessage"] = "An error occurred while updating the user. Please try again.";
                return View(updatedUser);
            }
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        [Authorize(Roles = "Admin")]
        public async Task<IActionResult> DeleteUser(int id)
        {
            if (await _userDAL.DeleteUserAsync(id))
            {
                return RedirectToAction("AdminUserManagement");
            }

            return NotFound();
        }

        [HttpGet]
        public IActionResult AccessDenied()
        {
            var user = User.Identity?.Name ?? "Anonymous";
            Console.WriteLine($"Access denied for user: {user}");
            return View();
        }

        [HttpGet]
        [Authorize(Roles = "Customer")] // Restrict to Customer role only
        public async Task<IActionResult> AddCreditCard()
        {
            var userId = HttpContext.Session.GetInt32("UserId");
            if (!userId.HasValue)
            {
                return RedirectToAction("Login");
            }

            // Get existing cards to display
            var userCards = await _creditCardDAL.GetUserCreditCardsAsync(userId.Value);
            ViewBag.ExistingCards = userCards;

            return View();
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        [Authorize(Roles = "Customer")]
        public async Task<IActionResult> AddCreditCard(CreditCardModel creditCard)
        {
            var userId = HttpContext.Session.GetInt32("UserId");
            if (!userId.HasValue)
            {
                return RedirectToAction("Login");
            }

            if (!ModelState.IsValid)
            {
                var errors = ModelState.Values
                    .SelectMany(v => v.Errors)
                    .Select(e => e.ErrorMessage);
                ViewData["ErrorMessage"] = string.Join(" ", errors);
                var userCards = await _creditCardDAL.GetUserCreditCardsAsync(userId.Value);
                ViewBag.ExistingCards = userCards;
                return View(creditCard);
            }

            // Check if the card number is unique
            if (!await _creditCardDAL.IsCardNumberUniqueAsync(creditCard.CardNumber))
            {
                ViewData["ErrorMessage"] = "This card number is already in use.";
                var userCards = await _creditCardDAL.GetUserCreditCardsAsync(userId.Value);
                ViewBag.ExistingCards = userCards;
                return View(creditCard);
            }

            try
            {
                // Create the credit card and associate it with the user using shadow property
                await _creditCardDAL.CreateCreditCardAsync(creditCard, userId.Value);
                TempData["Success"] = "Credit card added successfully.";
                return RedirectToAction("ShowUser", new { id = userId.Value });
            }
            catch (Exception ex)
            {
                ViewData["ErrorMessage"] = "An error occurred while adding the credit card: " + ex.Message;
                var userCards = await _creditCardDAL.GetUserCreditCardsAsync(userId.Value);
                ViewBag.ExistingCards = userCards;
                return View(creditCard);
            }
        }
    }
}