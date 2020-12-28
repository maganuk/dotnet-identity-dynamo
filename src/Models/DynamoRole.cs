using Amazon.DynamoDBv2.DataModel;
using Microsoft.AspNetCore.Identity;
using System;

namespace LiteBorder.AspNetCore.Identity.DynamoDb
{
    [DynamoDBTable("Auth")]
    public class DynamoRole : IdentityRole<string>
    {
        public DynamoRole()
        {
            Id = Guid.NewGuid().ToString();
            CreatedOn = DateTimeOffset.Now;
            Meta = Id;
        }

        public DynamoRole(string roleName) : this()
        {
            Name = roleName;
        }

        [DynamoDBHashKey]
        [DynamoDBProperty(typeof(RoleIdConverter))]
        public override string Id { get; set; }

        [DynamoDBGlobalSecondaryIndexHashKey("NormalizedRoleNameIndex")]
        [DynamoDBGlobalSecondaryIndexRangeKey("UserIdNormalizedRoleNameIndex")]
        public override string NormalizedName { get; set; }

        [DynamoDBProperty(typeof(RoleMetaConverter))]
        public string Meta { get; set; }


        [DynamoDBProperty(typeof(DateTimeOffsetConverter))]
        public DateTimeOffset CreatedOn { get; set; }

        [DynamoDBVersion]
        public int? VersionNumber { get; set; }
    }
}
