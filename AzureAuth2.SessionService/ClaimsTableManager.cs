using Azure;
using Azure.Data.Tables;
using System.Runtime.Serialization;
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

    public async Task<ClaimsEntity?> Get(Guid token)
    {
        var result = await claimsTable.GetEntityIfExistsAsync<ClaimsEntity?>("Claims", token.ToString());
        if(!result.HasValue) return null;
        return result.Value;
    }
    public async Task<ClaimsEntity> Store(ClaimsEntity entity) { await claimsTable.UpsertEntityAsync(entity); return entity; }
    public async Task Drop(Guid token) => await claimsTable.DeleteEntityAsync("Claims", token.ToString());
    
}

internal class ClaimsEntity : ITableEntity
{
    [IgnoreDataMember]public Guid RefreshToken { get; set; } = Guid.NewGuid();
    [IgnoreDataMember]public IEnumerable<Claim> ClaimSet { get; set; } = Enumerable.Empty<Claim>();

    public string Claims 
    { 
        get
        {
            using var targetStream = new MemoryStream();
            using var serializer = new BinaryWriter(targetStream);
            foreach (var claim in ClaimSet) claim.WriteTo(serializer);
            serializer.Flush();

            return Convert.ToBase64String(targetStream.ToArray());
        }
        set 
        {
            using var sourceStream = new MemoryStream(Convert.FromBase64String(value));
            using var deserializer = new BinaryReader(sourceStream);
            IEnumerable<Claim> claimsEnumerator()
            {
                while (sourceStream.Position < sourceStream.Length) 
                    yield return new Claim(deserializer);
            }

            ClaimSet = claimsEnumerator().ToList();
        }
    }
    string ITableEntity.PartitionKey { get; set; } = "Claims";
    string ITableEntity.RowKey { get => RefreshToken.ToString(); set => RefreshToken = Guid.Parse(value); }
    DateTimeOffset? ITableEntity.Timestamp { get; set; }
    ETag ITableEntity.ETag { get; set; }

    public static implicit operator ClaimsEntity(List<Claim> claims) => new() { ClaimSet = claims };
    public static implicit operator List<Claim>(ClaimsEntity entity) => entity.ClaimSet.ToList();
}
