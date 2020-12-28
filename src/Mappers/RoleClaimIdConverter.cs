using Amazon.DynamoDBv2.DataModel;
using Amazon.DynamoDBv2.DocumentModel;

namespace LiteBorder.AspNetCore.Identity.DynamoDb
{
    public class RoleClaimIdConverter : IPropertyConverter
    {
        public DynamoDBEntry ToEntry(object value)
        {
            return $"Role#{value}";
        }

        public object FromEntry(DynamoDBEntry entry)
        {
            return entry.AsString().Replace("Role#", "");
        }
    }
}
