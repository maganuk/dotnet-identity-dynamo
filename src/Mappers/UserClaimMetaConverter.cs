using Amazon.DynamoDBv2.DataModel;
using Amazon.DynamoDBv2.DocumentModel;

namespace LiteBorder.AspNetCore.Identity.DynamoDb
{
    public class UserClaimMetaConverter : IPropertyConverter
    {
        public DynamoDBEntry ToEntry(object value)
        {
            return $"UserClaim#{value}";
        }

        public object FromEntry(DynamoDBEntry entry)
        {
            return int.Parse(entry.AsString().Replace("UserClaim#", ""));
        }
    }
}
