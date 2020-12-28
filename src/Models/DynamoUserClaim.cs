using Amazon.DynamoDBv2.DataModel;
using Microsoft.AspNetCore.Identity;
using System;

namespace LiteBorder.AspNetCore.Identity.DynamoDb
{
    [DynamoDBTable("Auth")]
    public class DynamoUserClaim : IdentityUserClaim<string>
    {
        public DynamoUserClaim()
        {
            Random rnd = new Random();
            Id = rnd.Next(0, int.MaxValue);
        }

        [DynamoDBHashKey]
        [DynamoDBProperty("Id", typeof(UserClaimIdConverter))]
        public override string UserId { get; set; }

        [DynamoDBProperty("Meta", typeof(UserClaimMetaConverter))]
        public override int Id { get; set; }
    }
}
