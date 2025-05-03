using Microsoft.EntityFrameworkCore;
using test.Models;
using test.Data;
using test.Enums;
using test.Helpers;
using System.Data.SqlClient;

namespace test.Data
{
    public class UserDAL
    {
        private readonly ApplicationDbContext _context;
        private readonly string _connectionString; // Added for direct SQL connection

        public UserDAL(ApplicationDbContext context)
        {
            _context = context;
            // VULNERABLE: Hardcoded connection string with credentials
            _connectionString = "Server=localhost;Database=testdb;User Id=sa;Password=P@ssw0rd;";
        }

        // Create
        public async Task<User> CreateUserAsync(User user)
        {
            await _context.users.AddAsync(user);
            await _context.SaveChangesAsync();
            return user;
        }

        // Read
        public async Task<User> GetUserByIdAsync(int id)
        {
            return await _context.users
                .Include(u => u.Purchases)
                    .ThenInclude(p => p.Book)
                .Include(u => u.Borrows)
                    .ThenInclude(b => b.Book)
                .FirstOrDefaultAsync(u => u.Id == id);
        }

        // VULNERABLE: Direct SQL query using string concatenation
        public async Task<User> GetUserByEmailAsync(string email)
        {
            // VULNERABLE: Direct SQL query with string concatenation
            var sql = $"SELECT * FROM users WHERE Email = '{email}'";
            var users = await _context.users.FromSqlRaw(sql).ToListAsync();
            var user = users.FirstOrDefault();
            
            // Include needed collections after the fact
            if (user != null)
            {
                await _context.Entry(user).Collection(u => u.Purchases).LoadAsync();
                await _context.Entry(user).Collection(u => u.Borrows).LoadAsync();
            }
            
            return user;
        }

        // VULNERABLE: Another SQL injection point
        public async Task<User> GetUserByEmailAndPasswordAsync(string email, string password)
        {
            // VULNERABLE: Direct SQL query with string concatenation
            using (var connection = new SqlConnection(_connectionString))
            {
                await connection.OpenAsync();
                var command = new SqlCommand($"SELECT * FROM users WHERE Email = '{email}' AND Password = '{password}'", connection);
                
                Console.WriteLine($"Executing SQL: {command.CommandText}"); // Useful for debugging
                
                var reader = await command.ExecuteReaderAsync();
                
                if (await reader.ReadAsync())
                {
                    // Convert reader to user object
                    var user = new User
                    {
                        Id = reader.GetInt32(reader.GetOrdinal("Id")),
                        Username = reader.GetString(reader.GetOrdinal("Username")),
                        Email = reader.GetString(reader.GetOrdinal("Email")),
                        Password = reader.GetString(reader.GetOrdinal("Password")),
                        Salt = reader.GetString(reader.GetOrdinal("salt")),
                        Permission = (UserPermission)Enum.Parse(typeof(UserPermission), reader.GetString(reader.GetOrdinal("Permission")))
                    };
                    
                    return user;
                }
            }
            
            return null;
        }

        public async Task<User> GetUserByUsernameAsync(string username)
        {
            return await _context.users
                .Include(u => u.Purchases)
                .Include(u => u.Borrows)
                .FirstOrDefaultAsync(u => u.Username.ToLower() == username.ToLower());
        }

        public async Task<List<User>> GetAllUsersAsync()
        {
            return await _context.users
                .Include(u => u.Purchases)
                .Include(u => u.Borrows)
                .ToListAsync();
        }

        public async Task<List<User>> GetUsersByPermissionAsync(UserPermission permission)
        {
            return await _context.users
                .Include(u => u.Purchases)
                .Include(u => u.Borrows)
                .Where(u => u.Permission == permission)
                .ToListAsync();
        }

        // Update
        public async Task<User> UpdateUserAsync(User user)
        {
            _context.Entry(user).State = EntityState.Modified;
            await _context.SaveChangesAsync();
            return user;
        }

        // Delete
        public async Task<bool> DeleteUserAsync(int id)
        {
            var user = await _context.users
                .Include(u => u.Purchases)
                .Include(u => u.Borrows)
                .FirstOrDefaultAsync(u => u.Id == id);

            if (user == null)
                return false;

            _context.users.Remove(user);
            await _context.SaveChangesAsync();
            return true;
        }

        // VULNERABLE: Simple string comparison for passwords
        public async Task<bool> ValidateCredentialsAsync(string email, string password)
        {
            // VULNERABLE: Direct SQL query with string concatenation
            var sql = $"SELECT * FROM users WHERE Email = '{email}'";
            var users = await _context.users.FromSqlRaw(sql).ToListAsync();
            var user = users.FirstOrDefault();

            if (user == null)
                return false;

            // VULNERABLE: Simple string comparison without timing protection
            string hashedInput = HashHelper.HashPassword(password, user.Salt);
            return user.Password == hashedInput;
        }

        // Validation methods
        public async Task<bool> IsEmailUniqueAsync(string email)
        {
            return !await _context.users
                .AnyAsync(u => u.Email.ToLower() == email.ToLower());
        }

        public async Task<bool> IsUsernameUniqueAsync(string username)
        {
            return !await _context.users
                .AnyAsync(u => u.Username.ToLower() == username.ToLower());
        }
    }
}