using Azure;
using Azure.Data.Tables;
using Microsoft.Extensions.Configuration;

namespace AzureAuth2.SessionCleaner;

public class ClaimsTableRepository
{
    readonly TableClient claimsTable;
    public ClaimsTableRepository(IConfiguration configuration)
    {
        var connectionString = configuration.GetConnectionString("ClaimsStorage");
        TableServiceClient tableServiceClient = new(connectionString);
        claimsTable = tableServiceClient.GetTableClient("Claims");
        claimsTable.CreateIfNotExists();
    }

    public async Task<int> DropExpired()
    {
        int counter = 0;

        await foreach (var entity in claimsTable.QueryAsync<Entity>())
        {
            if(entity.Timestamp < DateTimeOffset.UtcNow.AddDays(-1))
            {
                await claimsTable.DeleteEntityAsync(entity.PartitionKey, entity.RowKey);
                counter++;
            }
        }
        return counter;
    }
    class Entity : ITableEntity
    {
        public string PartitionKey { get; set; } = string.Empty;
        public string RowKey { get; set; } = string.Empty;
        public DateTimeOffset? Timestamp { get; set; }
        public ETag ETag { get; set; }
    }
}
