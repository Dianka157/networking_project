
using Microsoft.EntityFrameworkCore;
using test.Data;
using Microsoft.AspNetCore.Authentication.Cookies;
using test;
using test.Services;

var builder = WebApplication.CreateBuilder(args);

// Add services to the container.
builder.Services.AddControllersWithViews()
    .AddRazorRuntimeCompilation();

// Add Authentication configuration
builder.Services.AddAuthentication(CookieAuthenticationDefaults.AuthenticationScheme)
    .AddCookie(options =>
    {
        options.LoginPath = "/Account/Login";
        options.LogoutPath = "/Account/Logout";
        options.AccessDeniedPath = "/Account/AccessDenied";
        options.Cookie.HttpOnly = true;
        options.Cookie.SecurePolicy = CookieSecurePolicy.Always;
        options.ExpireTimeSpan = TimeSpan.FromMinutes(60);
    });

// Configure PostgreSQL Database Context
builder.Services.AddDbContext<ApplicationDbContext>(options =>
    options.UseNpgsql(builder.Configuration.GetConnectionString("DefaultConnection")));

// Register all DAL services
builder.Services.AddScoped<BookDAL>();
builder.Services.AddScoped<UserDAL>();
builder.Services.AddScoped<PurchaseDAL>();
builder.Services.AddScoped<BorrowDAL>();
builder.Services.AddScoped<DiscountDAL>();
builder.Services.AddScoped<ShoppingCartDAL>();
builder.Services.AddScoped<CartItemDAL>();
builder.Services.AddScoped<WaitingListDAL>();
builder.Services.AddScoped<ReviewDAL>(); 
builder.Services.AddScoped<RatingDAL>();
builder.Services.AddScoped<CreditCardDAL>();
builder.Services.AddHttpContextAccessor();


// Configure EmailService
builder.Services.Configure<EmailConfiguration>(
    builder.Configuration.GetSection("EmailConfiguration"));
builder.Services.AddTransient<EmailService>();

// Register PaymentService
builder.Services.AddTransient<PaymentService>();

// Configure Stripe
builder.Services.Configure<StripeOptions>(builder.Configuration.GetSection("Stripe"));

// Configure Session
builder.Services.AddSession(options =>
{
    options.IdleTimeout = TimeSpan.FromMinutes(30);
    options.Cookie.HttpOnly = true;
    options.Cookie.IsEssential = true;
});

var app = builder.Build();

// Database initialization

/*
using (var scope = app.Services.CreateScope())
{
     var dbContext = scope.ServiceProvider.GetRequiredService<ApplicationDbContext>();
     dbContext.Database.EnsureDeleted();
     dbContext.Database.EnsureCreated();
}
*/


// Configure the HTTP request pipeline.
if (!app.Environment.IsDevelopment())
{
    app.UseExceptionHandler("/Home/Error");
    app.UseHsts();
}

app.UseHttpsRedirection();
app.UseStaticFiles();
app.UseRouting();

// Important: UseAuthentication must come before UseAuthorization
app.UseAuthentication();
app.UseAuthorization();

app.UseSession();
app.UseStaticFiles(); // Ensure this line is present to serve static files


app.MapControllerRoute(
    name: "default",
    pattern: "{controller=Home}/{action=Index}/{id?}");

app.Run();