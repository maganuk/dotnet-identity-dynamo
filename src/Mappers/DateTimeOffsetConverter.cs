using Amazon.DynamoDBv2.DataModel;
using Amazon.DynamoDBv2.DocumentModel;
using System;

namespace LiteBorder.AspNetCore.Identity.DynamoDb
{
    public class DateTimeOffsetConverter : IPropertyConverter
    {
        public DynamoDBEntry ToEntry(object value)
        {
            return ((DateTimeOffset)value).ToString("o");
        }

        public object FromEntry(DynamoDBEntry entry)
        {
            return DateTimeOffset.ParseExact(entry.AsString(), "o", null);
        }
    }
}
