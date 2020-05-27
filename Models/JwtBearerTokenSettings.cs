namespace JwtAuthAPI.Models
{
    public class JwtBearerTokenSettings
    {
        public string Secret { get; set; }
        public string Issuer { get; set; }
        public string Audience { get; set; }
        public double ExpiryTime { get; set; }
    }
}
