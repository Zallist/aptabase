using Aptabase.Data;
using System.Text;
using System.Security.Cryptography;
using Microsoft.Extensions.Caching.Memory;
using Dapper;
using FastHashes;

namespace Aptabase.Features.Privacy;

public interface IUserHasher
{
    Task<string> CalculateHash(DateTime timestamp, string appId, string sessionId, string clientIP, string userAgent);
}

public class DailyUserHasher : IUserHasher
{
    private readonly IMemoryCache _cache;
    private readonly IDbContext _db;

    public DailyUserHasher(IMemoryCache cache, IDbContext db)
    {
        _db = db ?? throw new ArgumentNullException(nameof(db));
        _cache = cache ?? throw new ArgumentNullException(nameof(cache));
    }

    public Task<string> CalculateHash(DateTime timestamp, string appId, string sessionId, string clientIP, string userAgent)
    {
        var cacheKey = $"USERID-{appId}-{sessionId}";

        // If we already have a cached user ID for this session, return it immediately
        // This avoid issues with the user ID changing in the middle of a session because of an IP change
        if (_cache.TryGetValue(cacheKey, out string? userId) && !string.IsNullOrEmpty(userId))
            return Task.FromResult(userId);

        var salt = GetSaltFor(appId);
        var bytes = Encoding.UTF8.GetBytes($"{clientIP}|${userAgent}");
        var hash = ComputeHash(salt, bytes);
        userId = Convert.ToHexString(hash);

        _cache.Set(cacheKey, userId, TimeSpan.FromHours(48));
        return Task.FromResult(userId);
    }

    private static byte[] ComputeHash(Span<byte> salt, byte[] bytes)
    {
        var key1 = BitConverter.ToUInt64(salt[..8]);
        var key2 = BitConverter.ToUInt64(salt[0..]);
        var hasher = new SipHash(SipHashVariant.V24, key1, key2);
        return hasher.ComputeHash(bytes);
    }

    private byte[] GetSaltFor(string appId)
    {
        var cacheKey = $"SALT-{appId}";
        if (_cache.TryGetValue(cacheKey, out byte[]? cachedSalt) && cachedSalt != null)
            return cachedSalt;

        var storedSalt = CreateSalt(appId);
        _cache.Set(cacheKey, storedSalt, TimeSpan.FromDays(2));
        return storedSalt;
    }

    private static byte[] CreateSalt(string appId)
    {
        var bytes = System.Text.Encoding.UTF8.GetBytes(appId);
        var hash = System.Security.Cryptography.Shake128.HashData(bytes, 16);
        if (hash.Length != 16)
        {
            Array.Resize(ref hash, 16);
        }

        return hash;
    }
}