using Amazon.DynamoDBv2.DataModel;
using Microsoft.AspNetCore.Identity;
using System;

namespace LiteBorder.AspNetCore.Identity.DynamoDb
{
    [DynamoDBTable("Auth")]
    public class DynamoUser : IdentityUser<string>
    {
        public DynamoUser()
        {
            Id = Guid.NewGuid().ToString();
            CreatedOn = DateTimeOffset.Now;
            Meta = Id;
        }

        public DynamoUser(string userName) : this()
        {
            UserName = userName ?? throw new ArgumentNullException(nameof(userName));
        }

        [DynamoDBHashKey]
        [DynamoDBProperty(typeof(UserIdConverter))]
        public override string Id { get; set; }

        [DynamoDBProperty(typeof(DateTimeOffsetConverter))]
        public override DateTimeOffset? LockoutEnd { get; set; }

        [DynamoDBGlobalSecondaryIndexHashKey("NormalizedEmailIndex")]
        public override string NormalizedEmail { get; set; }

        [DynamoDBGlobalSecondaryIndexHashKey("NormalizedUsernameIndex")]
        public override string NormalizedUserName { get; set; }

        [DynamoDBProperty(typeof(UserMetaConverter))]
        public string Meta { get; set; }

        [DynamoDBProperty(typeof(DateTimeOffsetConverter))]
        public DateTimeOffset CreatedOn { get; set; }

        [DynamoDBVersion]
        public int? VersionNumber { get; set; }
    }
}
