using Amazon.DynamoDBv2.DataModel;
using Amazon.DynamoDBv2.DocumentModel;

namespace LiteBorder.AspNetCore.Identity.DynamoDb
{
    public class RoleClaimMetaConverter : IPropertyConverter
    {
        public DynamoDBEntry ToEntry(object value)
        {
            return $"RoleClaim#{value}";
        }

        public object FromEntry(DynamoDBEntry entry)
        {
            return int.Parse(entry.AsString().Replace("RoleClaim#", ""));
        }
    }
}
