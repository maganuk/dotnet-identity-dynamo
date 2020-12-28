using Amazon.DynamoDBv2;
using Amazon.DynamoDBv2.DataModel;
using Amazon.DynamoDBv2.DocumentModel;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Options;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Threading;
using System.Threading.Tasks;

namespace LiteBorder.AspNetCore.Identity.DynamoDb
{
    public class DynamoRoleStore : IRoleStore<DynamoRole>, IQueryableRoleStore<DynamoRole>, IRoleClaimStore<DynamoRole>
    {
        private readonly DynamoIdentityOptions _options;
        private readonly DynamoDBContext _context;
        private readonly DynamoDBOperationConfig _dynamoConfig;

        public DynamoRoleStore(IAmazonDynamoDB client, IOptions<DynamoIdentityOptions> options)
        {
            _options = options.Value;
            _context = new DynamoDBContext(client);
            _dynamoConfig = new DynamoDBOperationConfig() { OverrideTableName = options.Value.DynamoTableName };
        }

        public IQueryable<DynamoRole> Roles => throw new NotImplementedException();

        public async Task<IdentityResult> CreateAsync(DynamoRole role, CancellationToken cancellationToken)
        {
            if (role == null)
            {
                throw new ArgumentNullException(nameof(role));
            }

            cancellationToken.ThrowIfCancellationRequested();

            await _context.SaveAsync(role, _dynamoConfig, cancellationToken);

            return IdentityResult.Success;
        }

        public async Task<DynamoRole> FindByNameAsync(string normalizedRoleName, CancellationToken cancellationToken)
        {
            if (normalizedRoleName == null)
            {
                throw new ArgumentNullException(nameof(normalizedRoleName));
            }

            cancellationToken.ThrowIfCancellationRequested();

            var search = _context.FromQueryAsync<DynamoRole>(new QueryOperationConfig
            {
                IndexName = "NormalizedRoleNameIndex",
                KeyExpression = new Expression
                {
                    ExpressionStatement = "NormalizedName = :name",
                    ExpressionAttributeValues = new Dictionary<string, DynamoDBEntry>
                    {
                        {":name", normalizedRoleName}
                    }
                },
                Limit = 1
            }, _dynamoConfig);
            var roles = await search.GetRemainingAsync(cancellationToken);
            return roles?.FirstOrDefault();
        }

        public Task SetNormalizedRoleNameAsync(DynamoRole role, string normalizedName, CancellationToken cancellationToken)
        {
            if (role == null)
            {
                throw new ArgumentNullException(nameof(role));
            }

            if (normalizedName != null)
            {
                role.NormalizedName = normalizedName;
            }

            return Task.FromResult(0);
        }

        public Task<string> GetRoleNameAsync(DynamoRole role, CancellationToken cancellationToken)
        {
            if (role == null)
            {
                throw new ArgumentNullException(nameof(role));
            }

            return Task.FromResult(role.Name);
        }

        public Task<string> GetNormalizedRoleNameAsync(DynamoRole role, CancellationToken cancellationToken)
        {
            if (role == null)
            {
                throw new ArgumentNullException(nameof(role));
            }

            return Task.FromResult(role.NormalizedName);
        }

        public Task<string> GetRoleIdAsync(DynamoRole role, CancellationToken cancellationToken)
        {
            if (role == null)
            {
                throw new ArgumentNullException(nameof(role));
            }

            return Task.FromResult(role.Id);
        }

        public async Task<DynamoRole> FindByIdAsync(string roleId, CancellationToken cancellationToken)
        {
            if (roleId == null)
            {
                throw new ArgumentNullException(nameof(roleId));
            }

            cancellationToken.ThrowIfCancellationRequested();

            var role = await _context.LoadAsync<DynamoRole>(roleId, roleId, _dynamoConfig, cancellationToken);
            return role;
        }

        public async Task<IdentityResult> UpdateAsync(DynamoRole role, CancellationToken cancellationToken)
        {
            if (role == null)
            {
                throw new ArgumentNullException(nameof(role));
            }

            cancellationToken.ThrowIfCancellationRequested();

            await _context.SaveAsync(role, _dynamoConfig, cancellationToken);

            return IdentityResult.Success;
        }

        public Task SetRoleNameAsync(DynamoRole role, string roleName, CancellationToken cancellationToken)
        {
            if (role == null)
            {
                throw new ArgumentNullException(nameof(role));
            }

            if (roleName != null)
            {
                role.Name = roleName;
            }

            return Task.FromResult(0);
        }

        public async Task<IList<Claim>> GetClaimsAsync(DynamoRole role, CancellationToken cancellationToken = default)
        {
            if (role == null)
            {
                throw new ArgumentNullException(nameof(role));
            }

            cancellationToken.ThrowIfCancellationRequested();

            var search = _context.FromQueryAsync<DynamoRoleClaim>(new QueryOperationConfig
            {
                KeyExpression = new Expression
                {
                    ExpressionStatement = "Id = :roleId AND begins_with(Meta, :claim)",
                    ExpressionAttributeValues = new Dictionary<string, DynamoDBEntry>
                    {
                        {":roleId", $"Role#{role.Id}"},
                        {":claim", "RoleClaim#" }
                    }
                }
            }, _dynamoConfig);

            var roleClaims = await search.GetRemainingAsync(cancellationToken);

            return roleClaims.Select(x => new Claim(x.ClaimType, x.ClaimValue)).ToList();
        }

        public async Task AddClaimAsync(DynamoRole role, Claim claim, CancellationToken cancellationToken = default)
        {
            if (role == null)
            {
                throw new ArgumentNullException(nameof(role));
            }

            if (claim == null)
            {
                throw new ArgumentNullException(nameof(claim));
            }

            var existingClaimsSearch = _context.FromQueryAsync<DynamoRoleClaim>(new QueryOperationConfig
            {
                KeyExpression = new Expression
                {
                    ExpressionStatement = "Id = :roleId AND begins_with(Meta, :claim)",
                    ExpressionAttributeValues = new Dictionary<string, DynamoDBEntry>
                    {
                        {":roleId", $"Role#{role.Id}"},
                        {":claim", "RoleClaim#" }
                    }
                },
                FilterExpression = new Expression
                {
                    ExpressionStatement = "ClaimType = :claimType AND ClaimValue = :claimValue",
                    ExpressionAttributeValues = new Dictionary<string, DynamoDBEntry>
                    {
                        {":claimType", claim.Type},
                        {":claimValue", claim.Value }
                    }
                },
                Limit = 1
            }, _dynamoConfig);

            var existingClaim = (await existingClaimsSearch.GetRemainingAsync(cancellationToken)).FirstOrDefault();

            if (existingClaim == null)
            {
                var roleClaim = new DynamoRoleClaim()
                {
                    RoleId = role.Id,
                    ClaimType = claim.Type,
                    ClaimValue = claim.Value
                };

                await _context.SaveAsync(roleClaim, _dynamoConfig, cancellationToken);
            }
        }

        public async Task RemoveClaimAsync(DynamoRole role, Claim claim, CancellationToken cancellationToken = default)
        {
            if (role == null)
            {
                throw new ArgumentNullException(nameof(role));
            }

            if (claim == null)
            {
                throw new ArgumentNullException(nameof(claim));
            }

            var existingClaimsSearch = _context.FromQueryAsync<DynamoRoleClaim>(new QueryOperationConfig
            {
                KeyExpression = new Expression
                {
                    ExpressionStatement = "Id = :roleId AND begins_with(Meta, :claim)",
                    ExpressionAttributeValues = new Dictionary<string, DynamoDBEntry>
                    {
                        {":roleId", $"Role#{role.Id}"},
                        {":claim", "RoleClaim#" }
                    }
                },
                FilterExpression = new Expression
                {
                    ExpressionStatement = "ClaimType = :claimType AND ClaimValue = :claimValue",
                    ExpressionAttributeValues = new Dictionary<string, DynamoDBEntry>
                    {
                        {":claimType", claim.Type},
                        {":claimValue", claim.Value }
                    }
                },
                Limit = 1
            }, _dynamoConfig);

            var existingClaim = (await existingClaimsSearch.GetRemainingAsync(cancellationToken)).FirstOrDefault();

            if (existingClaim != null)
            {
                await _context.DeleteAsync(existingClaim, _dynamoConfig, cancellationToken);
            }
        }

        public async Task<IdentityResult> DeleteAsync(DynamoRole role, CancellationToken cancellationToken)
        {
            if (role == null)
            {
                throw new ArgumentNullException(nameof(role));
            }

            cancellationToken.ThrowIfCancellationRequested();

            var search = _context.FromQueryAsync<DynamoRole>(new QueryOperationConfig
            {
                IndexName = "MetaIndex",
                KeyExpression = new Expression
                {
                    ExpressionStatement = "Meta = :roleId",
                    ExpressionAttributeValues = new Dictionary<string, DynamoDBEntry>
                    {
                        {":roleId", $"Role#{role.Id}"}
                    }
                }
            }, _dynamoConfig);

            var roleInUse = (await search.GetRemainingAsync(cancellationToken)).Where(x => x.Id != x.Meta);

            if (roleInUse.Any())
            {
                throw new ArgumentException("Role is in use", nameof(role));
            }

            var roleToDelete = await _context.LoadAsync<DynamoRole>(role.Id, role.Id, _dynamoConfig, cancellationToken);
            var roleBatch = _context.CreateBatchWrite<DynamoRole>(new DynamoDBOperationConfig() { OverrideTableName = _options.DynamoTableName, SkipVersionCheck = true });
            roleBatch.AddDeleteItem(roleToDelete);

            var roleClaims = await _context.FromQueryAsync<DynamoRoleClaim>(new QueryOperationConfig()
            {
                KeyExpression = new Expression()
                {
                    ExpressionStatement = "Id = :roleId AND begins_with(Meta, :claim)",
                    ExpressionAttributeValues = new Dictionary<string, DynamoDBEntry>
                    {
                        {":roleId", $"Role#{role.Id}"},
                        {":claim", "RoleClaim#" }
                    }
                }
            }, _dynamoConfig).GetRemainingAsync(cancellationToken);

            var roleClaimsBatch = _context.CreateBatchWrite<DynamoRoleClaim>(_dynamoConfig);
            foreach (var item in roleClaims)
            {
                roleClaimsBatch.AddDeleteItem(item);
            }

            var batch = roleBatch.Combine(roleClaimsBatch);

            await batch.ExecuteAsync(cancellationToken);

            return IdentityResult.Success;
        }

#pragma warning disable CA1816 // Dispose methods should call SuppressFinalize
        public void Dispose() { }
#pragma warning restore CA1816 // Dispose methods should call SuppressFinalize
    }
}
