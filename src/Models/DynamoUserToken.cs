using Amazon.DynamoDBv2.DataModel;
using Microsoft.AspNetCore.Identity;
using System;

namespace LiteBorder.AspNetCore.Identity.DynamoDb
{
    [DynamoDBTable("Auth")]
    public class DynamoUserToken : IdentityUserToken<string>
    {
        public DynamoUserToken()
        {
            Meta = Guid.NewGuid().ToString();
        }

        [DynamoDBProperty("Id", typeof(UserTokenIdConverter))]
        public override string UserId { get; set; }

        [DynamoDBProperty("Meta", typeof(UserTokenMetaConverter))]
        public string Meta { get; set; }

        [DynamoDBProperty("TokenName")]
        public override string Name { get; set; }
    }
}
