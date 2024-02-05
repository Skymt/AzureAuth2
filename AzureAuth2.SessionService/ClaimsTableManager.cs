using Azure;
using Azure.Data.Tables;
using System.Security.Claims;

internal class ClaimsTableRepository
{
    readonly TableClient claimsTable;
    public ClaimsTableRepository(IConfiguration configuration)
    {
        var connectionString = configuration.GetConnectionString("ClaimsStorage");
        TableServiceClient tableServiceClient = new(connectionString);
        claimsTable = tableServiceClient.GetTableClient("Claims");
        claimsTable.CreateIfNotExists();
    }

    public async Task<List<Claim>?> Get(Guid token)
    {
        var result = await claimsTable.GetEntityIfExistsAsync<ClaimsEntity?>("Claims", token.ToString());
        if (!result.HasValue) return null;
        return result.Value!;
    }
    public async Task<Guid> Set(List<Claim> claims)
    {
        ClaimsEntity entity = claims;
        await claimsTable.UpsertEntityAsync(entity);
        return Guid.Parse(entity.RowKey);
    }
    public async Task Drop(Guid token) =>
        await claimsTable.DeleteEntityAsync("Claims", token.ToString());

    private class ClaimsEntity : ITableEntity
    {
        public string Claims { get; set; } = string.Empty;
        public string RowKey { get; set; } = $"{Guid.NewGuid()}";
        public string PartitionKey { get; set; } = "Claims";
        public DateTimeOffset? Timestamp { get; set; }
        public ETag ETag { get; set; }

        public static implicit operator ClaimsEntity(List<Claim> claims)
        {
            using var targetStream = new MemoryStream();
            using var serializer = new BinaryWriter(targetStream);
            claims.ForEach(claim => claim.WriteTo(serializer));
            serializer.Flush();

            return new ClaimsEntity() { Claims = Convert.ToBase64String(targetStream.ToArray()) };
        }
        public static implicit operator List<Claim>(ClaimsEntity entity)
        {
            using var sourceStream = new MemoryStream(Convert.FromBase64String(entity.Claims));
            using var deserializer = new BinaryReader(sourceStream);
            IEnumerable<Claim> claimsEnumerator()
            {
                while (sourceStream.Position < sourceStream.Length)
                    yield return new Claim(deserializer);
            }

            return claimsEnumerator().ToList();
        }
    }
}