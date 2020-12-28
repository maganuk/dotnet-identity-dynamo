using Amazon.DynamoDBv2.DataModel;
using Microsoft.AspNetCore.Identity;
using System;

namespace LiteBorder.AspNetCore.Identity.DynamoDb
{
    [DynamoDBTable("Auth")]
    public class DynamoRoleClaim : IdentityRoleClaim<string>
    {
        public DynamoRoleClaim()
        {
            Random rnd = new Random();
            Id = rnd.Next(0, int.MaxValue);
        }

        [DynamoDBHashKey]
        [DynamoDBProperty("Id", typeof(RoleClaimIdConverter))]
        public override string RoleId { get; set; }

        [DynamoDBProperty("Meta", typeof(RoleClaimMetaConverter))]
        public override int Id { get; set; }
    }
}
