using Amazon.DynamoDBv2.DataModel;
using Microsoft.AspNetCore.Identity;

namespace LiteBorder.AspNetCore.Identity.DynamoDb
{
    [DynamoDBTable("Auth")]
    public class DynamoUserLogin : IdentityUserLogin<string>
    {
        [DynamoDBHashKey]
        [DynamoDBProperty("Id", typeof(UserLoginIdConverter))]
        public override string UserId { get; set; }

        [DynamoDBProperty("Meta", typeof(UserLoginMetaConverter))]
        public override string ProviderKey { get; set; }
    }
}
