using Amazon.DynamoDBv2.DataModel;
using Amazon.DynamoDBv2.DocumentModel;

namespace LiteBorder.AspNetCore.Identity.DynamoDb
{
    public class UserLoginMetaConverter : IPropertyConverter
    {
        public DynamoDBEntry ToEntry(object value)
        {
            return $"UserLogin#{value}";
        }

        public object FromEntry(DynamoDBEntry entry)
        {
            return entry.AsString().Replace("UserLogin#", "");
        }
    }
}
