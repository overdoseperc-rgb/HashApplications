using System.Security.Cryptography;
using System.Text;

internal sealed class UserCredentials
{
    public required byte[] Salt { get; init; }
    public required byte[] PasswordHash { get; init; }
}

internal static class Program
{
    private static readonly Dictionary<string, UserCredentials> Users = new(StringComparer.Ordinal);

    private static void Main()
    {
        while (true)
        {
            Console.WriteLine("\n=== Система аутентификации ===");
            Console.WriteLine("[1] Регистрация");
            Console.WriteLine("[2] Вход");
            Console.WriteLine("[0] Выход");
            Console.Write("Выберите действие: ");

            switch (Console.ReadLine())
            {
                case "1": SignUp(); break;
                case "2": LogIn(); break;
                case "0": return;
                default: Console.WriteLine("Неизвестная команда."); break;
            }
        }
    }

    private static void SignUp()
    {
        Console.Write("Введите имя пользователя: ");
        string? username = Console.ReadLine()?.Trim();
        if (string.IsNullOrWhiteSpace(username))
        {
            Console.WriteLine("Имя пользователя не может быть пустым.");
            return;
        }
        if (Users.ContainsKey(username))
        {
            Console.WriteLine("Пользователь уже существует.");
            return;
        }

        string password = ReadPassword("Введите пароль: ");
        string confirmation = ReadPassword("Подтвердите пароль: ");
        if (password.Length == 0 || password != confirmation)
        {
            Console.WriteLine("Пароль пуст или подтверждение не совпало.");
            return;
        }

        byte[] salt = new byte[16];
        using (RandomNumberGenerator generator = RandomNumberGenerator.Create())
        {
            generator.GetBytes(salt);
        }

        Users.Add(username, new UserCredentials
        {
            Salt = salt,
            PasswordHash = HashPassword(password, salt)
        });
        Console.WriteLine("Регистрация прошла успешно!");
    }

    private static void LogIn()
    {
        Console.Write("Введите имя пользователя: ");
        string? username = Console.ReadLine()?.Trim();
        string password = ReadPassword("Введите пароль: ");
        if (username is null || !Users.TryGetValue(username, out UserCredentials? credentials))
        {
            Console.WriteLine("Пользователь не найден.");
            return;
        }

        byte[] hash = HashPassword(password, credentials.Salt);
        if (CryptographicOperations.FixedTimeEquals(hash, credentials.PasswordHash))
        {
            Console.WriteLine($"Добро пожаловать, {username}!");
        }
        else
        {
            Console.WriteLine("Ошибка: Неверный пароль.");
        }
    }

    private static byte[] HashPassword(string password, byte[] salt)
    {
        byte[] passwordBytes = Encoding.UTF8.GetBytes(password);
        byte[] combinedBytes = new byte[passwordBytes.Length + salt.Length];
        Buffer.BlockCopy(passwordBytes, 0, combinedBytes, 0, passwordBytes.Length);
        Buffer.BlockCopy(salt, 0, combinedBytes, passwordBytes.Length, salt.Length);
        byte[] hash = SHA256.HashData(combinedBytes);
        CryptographicOperations.ZeroMemory(passwordBytes);
        CryptographicOperations.ZeroMemory(combinedBytes);
        return hash;
    }

    private static string ReadPassword(string prompt)
    {
        Console.Write(prompt);
        StringBuilder password = new();
        while (true)
        {
            ConsoleKeyInfo key = Console.ReadKey(intercept: true);
            if (key.Key == ConsoleKey.Enter)
            {
                Console.WriteLine();
                return password.ToString();
            }
            if (key.Key == ConsoleKey.Backspace)
            {
                if (password.Length > 0)
                {
                    password.Length--;
                    Console.Write("\b \b");
                }
            }
            else if (!char.IsControl(key.KeyChar))
            {
                password.Append(key.KeyChar);
                Console.Write('*');
            }
        }
    }
}
