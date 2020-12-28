using Amazon.DynamoDBv2.DataModel;
using Microsoft.AspNetCore.Identity;

namespace LiteBorder.AspNetCore.Identity.DynamoDb
{
    [DynamoDBTable("Auth")]
    public class DynamoUserRole : IdentityUserRole<string>
    {
        [DynamoDBHashKey]
        [DynamoDBProperty("Id", typeof(UserRoleIdConverter))]
        public override string UserId { get; set; }

        [DynamoDBProperty("Meta", typeof(UserRoleMetaConverter))]
        public override string RoleId { get; set; }
    }
}
