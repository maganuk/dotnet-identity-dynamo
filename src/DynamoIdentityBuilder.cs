using Amazon.DynamoDBv2;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.DependencyInjection;
using System;

namespace LiteBorder.AspNetCore.Identity.DynamoDb
{
    public static class IdentityEntityFrameworkBuilderExtensions
    {
        public static IdentityBuilder AddDynamoDbStores(this IdentityBuilder builder, Action<DynamoIdentityOptions> configure = null)
        {
            if (configure != null)
            {
                builder.Services.Configure(configure);
            }

            builder.Services.AddAWSService<IAmazonDynamoDB>();
            builder.Services.AddTransient<IUserStore<DynamoUser>, DynamoUserStore>();
            builder.Services.AddTransient<IRoleStore<DynamoRole>, DynamoRoleStore>();
            return builder;
        }
    }
}
