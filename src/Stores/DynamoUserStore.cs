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
    public class DynamoUserStore : IUserStore<DynamoUser>,
            IUserLoginStore<DynamoUser>,
            IUserPasswordStore<DynamoUser>,
            IUserSecurityStampStore<DynamoUser>,
            IUserTwoFactorStore<DynamoUser>,
            IUserEmailStore<DynamoUser>,
            IUserLockoutStore<DynamoUser>,
            IUserPhoneNumberStore<DynamoUser>,
            IUserRoleStore<DynamoUser>,
            IUserClaimStore<DynamoUser>,
            IProtectedUserStore<DynamoUser>,
            IQueryableUserStore<DynamoUser>,
            IUserAuthenticationTokenStore<DynamoUser>,
            IUserAuthenticatorKeyStore<DynamoUser>,
            IUserTwoFactorRecoveryCodeStore<DynamoUser>
    {
        private readonly DynamoIdentityOptions _options;
        private readonly DynamoDBContext _context;
        private readonly DynamoDBOperationConfig _dynamoConfig;
        private readonly RoleManager<DynamoRole> _roleManager;
        private const string AuthenticatorStoreLoginProvider = "[AspNetAuthenticatorStore]";
        private const string AuthenticatorKeyTokenName = "AuthenticatorKey";
        private const string RecoveryCodeTokenName = "RecoveryCodes";

        public DynamoUserStore(IAmazonDynamoDB client, RoleManager<DynamoRole> roleManager, IOptions<DynamoIdentityOptions> options)
        {
            _options = options.Value;
            _context = new DynamoDBContext(client);
            _dynamoConfig = new DynamoDBOperationConfig() { OverrideTableName = options.Value.DynamoTableName };
            _roleManager = roleManager;
        }

        public IQueryable<DynamoUser> Users => throw new NotImplementedException();

        public async Task<IdentityResult> CreateAsync(DynamoUser user, CancellationToken cancellationToken)
        {
            if (user == null)
            {
                throw new ArgumentNullException(nameof(user));
            }

            cancellationToken.ThrowIfCancellationRequested();

            await _context.SaveAsync(user, _dynamoConfig, cancellationToken);

            return IdentityResult.Success;
        }

        public async Task<DynamoUser> FindByEmailAsync(string normalizedEmail, CancellationToken cancellationToken)
        {
            if (normalizedEmail == null)
            {
                throw new ArgumentNullException(nameof(normalizedEmail));
            }

            cancellationToken.ThrowIfCancellationRequested();

            return (await _context.FromQueryAsync<DynamoUser>(new QueryOperationConfig
            {
                IndexName = "NormalizedEmailIndex",
                KeyExpression = new Expression
                {
                    ExpressionStatement = "NormalizedEmail = :email",
                    ExpressionAttributeValues = new Dictionary<string, DynamoDBEntry>
                    {
                        {":email", normalizedEmail}
                    }
                },
                Limit = 1
            }, _dynamoConfig).GetRemainingAsync(cancellationToken))?.FirstOrDefault();
        }

        public async Task<DynamoUser> FindByNameAsync(string normalizedUserName, CancellationToken cancellationToken)
        {
            if (normalizedUserName == null)
            {
                throw new ArgumentNullException(nameof(normalizedUserName));
            }

            cancellationToken.ThrowIfCancellationRequested();

            var search = _context.FromQueryAsync<DynamoUser>(new QueryOperationConfig
            {
                IndexName = "NormalizedUsernameIndex",
                KeyExpression = new Expression
                {
                    ExpressionStatement = "NormalizedUsername = :name",
                    ExpressionAttributeValues = new Dictionary<string, DynamoDBEntry>
                    {
                        {":name", normalizedUserName}
                    }
                },
                Limit = 1
            }, _dynamoConfig);
            var users = await search.GetRemainingAsync(cancellationToken);
            return users?.FirstOrDefault();
        }

        public async Task<DynamoUser> FindByIdAsync(string userId, CancellationToken cancellationToken)
        {
            if (userId == null)
            {
                throw new ArgumentNullException(nameof(userId));
            }

            cancellationToken.ThrowIfCancellationRequested();

            var user = await _context.LoadAsync<DynamoUser>(userId, userId, _dynamoConfig, cancellationToken);
            return user;
        }

        public async Task<IdentityResult> UpdateAsync(DynamoUser user, CancellationToken cancellationToken)
        {
            if (user == null)
            {
                throw new ArgumentNullException(nameof(user));
            }

            cancellationToken.ThrowIfCancellationRequested();

            await _context.SaveAsync(user, _dynamoConfig, cancellationToken);

            return IdentityResult.Success;
        }

        public Task<bool> GetLockoutEnabledAsync(DynamoUser user, CancellationToken cancellationToken)
        {
            if (user == null)
            {
                throw new ArgumentNullException(nameof(user));
            }

            return Task.FromResult(user.LockoutEnabled);
        }

        public Task SetLockoutEnabledAsync(DynamoUser user, bool enabled, CancellationToken cancellationToken)
        {
            if (user == null)
            {
                throw new ArgumentNullException(nameof(user));
            }

            user.LockoutEnabled = enabled;

            return Task.FromResult(0);
        }

        public Task SetEmailAsync(DynamoUser user, string email, CancellationToken cancellationToken)
        {
            if (user == null)
            {
                throw new ArgumentNullException(nameof(user));
            }

            user.Email = email ?? throw new ArgumentNullException(nameof(email));

            return Task.FromResult(0);
        }

        public Task<string> GetEmailAsync(DynamoUser user, CancellationToken cancellationToken)
        {
            if (user == null)
            {
                throw new ArgumentNullException(nameof(user));
            }

            return Task.FromResult(user.Email);
        }

        public Task<bool> GetEmailConfirmedAsync(DynamoUser user, CancellationToken cancellationToken)
        {
            if (user == null)
            {
                throw new ArgumentNullException(nameof(user));
            }

            if (user.Email == null)
            {
                throw new InvalidOperationException(
                    "Cannot get the confirmation status of the e-mail since the user doesn't have an e-mail.");
            }

            return Task.FromResult(user.EmailConfirmed);
        }

        public Task SetEmailConfirmedAsync(DynamoUser user, bool confirmed, CancellationToken cancellationToken)
        {
            if (user == null)
            {
                throw new ArgumentNullException(nameof(user));
            }

            if (user.Email == null)
            {
                throw new InvalidOperationException(
                    "Cannot set the confirmation status of the e-mail because user doesn't have an e-mail.");
            }

            user.EmailConfirmed = confirmed;

            return Task.FromResult(0);
        }

        public Task<string> GetNormalizedEmailAsync(DynamoUser user, CancellationToken cancellationToken)
        {
            if (user == null)
            {
                throw new ArgumentNullException(nameof(user));
            }

            return Task.FromResult(user.NormalizedEmail);
        }

        public Task SetNormalizedEmailAsync(DynamoUser user, string normalizedEmail, CancellationToken cancellationToken)
        {
            if (user == null)
            {
                throw new ArgumentNullException(nameof(user));
            }

            if (normalizedEmail != null)
            {
                user.NormalizedEmail = normalizedEmail;
            }

            return Task.FromResult(0);
        }

        public Task ResetAccessFailedCountAsync(DynamoUser user, CancellationToken cancellationToken)
        {
            if (user == null)
            {
                throw new ArgumentNullException(nameof(user));
            }

            user.AccessFailedCount = 0;

            return Task.FromResult(0);
        }

        public Task<string> GetUserIdAsync(DynamoUser user, CancellationToken cancellationToken)
        {
            if (user == null)
            {
                throw new ArgumentNullException(nameof(user));
            }

            return Task.FromResult(user.Id);
        }

        public Task<string> GetUserNameAsync(DynamoUser user, CancellationToken cancellationToken)
        {
            if (user == null)
            {
                throw new ArgumentNullException(nameof(user));
            }

            return Task.FromResult(user.UserName);
        }

        public Task SetNormalizedUserNameAsync(DynamoUser user, string normalizedName, CancellationToken cancellationToken)
        {
            if (user == null)
            {
                throw new ArgumentNullException(nameof(user));
            }

            user.NormalizedUserName = normalizedName ?? throw new ArgumentNullException(nameof(normalizedName));

            return Task.FromResult(0);
        }

        public Task<DateTimeOffset?> GetLockoutEndDateAsync(DynamoUser user, CancellationToken cancellationToken)
        {
            if (user == null)
            {
                throw new ArgumentNullException(nameof(user));
            }

            return Task.FromResult(user.LockoutEnd);
        }

        public Task SetLockoutEndDateAsync(DynamoUser user, DateTimeOffset? lockoutEnd, CancellationToken cancellationToken)
        {
            if (user == null)
            {
                throw new ArgumentNullException(nameof(user));
            }

            if (lockoutEnd != null)
            {
                user.LockoutEnd = lockoutEnd.Value;
            }

            return Task.FromResult(0);
        }

        public Task<int> GetAccessFailedCountAsync(DynamoUser user, CancellationToken cancellationToken)
        {
            if (user == null)
            {
                throw new ArgumentNullException(nameof(user));
            }

            return Task.FromResult(user.AccessFailedCount);
        }

        public Task<string> GetNormalizedUserNameAsync(DynamoUser user, CancellationToken cancellationToken)
        {
            if (user == null)
            {
                throw new ArgumentNullException(nameof(user));
            }

            return Task.FromResult(user.NormalizedUserName);
        }

        public Task SetPasswordHashAsync(DynamoUser user, string passwordHash, CancellationToken cancellationToken)
        {
            if (user == null)
            {
                throw new ArgumentNullException(nameof(user));
            }

            user.PasswordHash = passwordHash;

            return Task.FromResult(0);
        }

        public Task<string> GetPasswordHashAsync(DynamoUser user, CancellationToken cancellationToken)
        {
            if (user == null)
            {
                throw new ArgumentNullException(nameof(user));
            }

            return Task.FromResult(user.PasswordHash);
        }

        public Task<bool> HasPasswordAsync(DynamoUser user, CancellationToken cancellationToken)
        {
            if (user == null)
            {
                throw new ArgumentNullException(nameof(user));
            }

            return Task.FromResult(user.PasswordHash != null);
        }

        public Task SetPhoneNumberAsync(DynamoUser user, string phoneNumber, CancellationToken cancellationToken)
        {
            if (user == null)
            {
                throw new ArgumentNullException(nameof(user));
            }

            user.PhoneNumber = phoneNumber ?? throw new ArgumentNullException(nameof(phoneNumber));

            return Task.FromResult(0);
        }

        public Task<string> GetPhoneNumberAsync(DynamoUser user, CancellationToken cancellationToken)
        {
            if (user == null)
            {
                throw new ArgumentNullException(nameof(user));
            }

            return Task.FromResult(user.PhoneNumber);
        }

        public Task<bool> GetPhoneNumberConfirmedAsync(DynamoUser user, CancellationToken cancellationToken)
        {
            if (user == null)
            {
                throw new ArgumentNullException(nameof(user));
            }

            if (user.PhoneNumber == null)
            {
                throw new InvalidOperationException("Cannot get the confirmation status of the phone number since the user doesn't have a phone number.");
            }

            return Task.FromResult(user.PhoneNumberConfirmed);
        }

        public Task SetPhoneNumberConfirmedAsync(DynamoUser user, bool confirmed, CancellationToken cancellationToken)
        {
            if (user == null)
            {
                throw new ArgumentNullException(nameof(user));
            }

            if (user.PhoneNumber == null)
            {
                throw new InvalidOperationException(
                    "Cannot set the confirmation status of the phone number since the user doesn't have a phone number.");
            }

            user.PhoneNumberConfirmed = true;

            return Task.FromResult(0);
        }

        public Task SetSecurityStampAsync(DynamoUser user, string stamp, CancellationToken cancellationToken)
        {
            if (user == null)
            {
                throw new ArgumentNullException(nameof(user));
            }

            user.SecurityStamp = stamp ?? throw new ArgumentNullException(nameof(stamp));

            return Task.FromResult(0);
        }

        public Task<string> GetSecurityStampAsync(DynamoUser user, CancellationToken cancellationToken)
        {
            if (user == null)
            {
                throw new ArgumentNullException(nameof(user));
            }

            return Task.FromResult(user.SecurityStamp);
        }

        public Task SetTwoFactorEnabledAsync(DynamoUser user, bool enabled, CancellationToken cancellationToken)
        {
            if (user == null)
            {
                throw new ArgumentNullException(nameof(user));
            }

            user.TwoFactorEnabled = enabled;

            return Task.FromResult(0);
        }

        public Task<bool> GetTwoFactorEnabledAsync(DynamoUser user, CancellationToken cancellationToken)
        {
            if (user == null)
            {
                throw new ArgumentNullException(nameof(user));
            }

            return Task.FromResult(user.TwoFactorEnabled);
        }

        public Task SetUserNameAsync(DynamoUser user, string userName, CancellationToken cancellationToken)
        {
            if (user == null)
            {
                throw new ArgumentNullException(nameof(user));
            }

            user.UserName = userName ?? throw new ArgumentNullException(nameof(userName));

            return Task.FromResult(0);
        }

        public async Task<bool> IsInRoleAsync(DynamoUser user, string normalisedRoleName, CancellationToken cancellationToken)
        {
            if (user == null)
            {
                throw new ArgumentNullException(nameof(user));
            }

            if (normalisedRoleName == null)
            {
                throw new ArgumentNullException(nameof(normalisedRoleName));
            }

            cancellationToken.ThrowIfCancellationRequested();

            var role = await _roleManager.FindByNameAsync(normalisedRoleName);

            if (role == null)
            {
                throw new ArgumentOutOfRangeException(nameof(normalisedRoleName));
            }

            var userRole = await _context.LoadAsync<DynamoUserRole>(user.Id, role.Id, _dynamoConfig, cancellationToken);

            return userRole != null;
        }

        public async Task AddToRoleAsync(DynamoUser user, string normalisedRoleName, CancellationToken cancellationToken)
        {
            if (user == null)
            {
                throw new ArgumentNullException(nameof(user));
            }

            cancellationToken.ThrowIfCancellationRequested();

            var role = await _roleManager.FindByNameAsync(normalisedRoleName);

            var userRole = new DynamoUserRole()
            {
                UserId = user.Id,
                RoleId = role.Id
            };

            await _context.SaveAsync(userRole, _dynamoConfig, cancellationToken);
        }

        public async Task RemoveFromRoleAsync(DynamoUser user, string normalisedRoleName, CancellationToken cancellationToken)
        {
            if (user == null)
            {
                throw new ArgumentNullException(nameof(user));
            }

            if (normalisedRoleName == null)
            {
                throw new ArgumentNullException(nameof(normalisedRoleName));
            }

            cancellationToken.ThrowIfCancellationRequested();

            var role = await _roleManager.FindByNameAsync(normalisedRoleName);

            if (role != null)
            {
                var userRole = await _context.LoadAsync<DynamoUserRole>(user.Id, role.Id, _dynamoConfig, cancellationToken);

                if (userRole != null)
                {
                    await _context.DeleteAsync(userRole, _dynamoConfig, cancellationToken);
                }
            }
        }

        public async Task<IList<string>> GetRolesAsync(DynamoUser user, CancellationToken cancellationToken)
        {
            if (user == null)
            {
                throw new ArgumentNullException(nameof(user));
            }

            cancellationToken.ThrowIfCancellationRequested();

            var search = _context.FromQueryAsync<DynamoUserRole>(new QueryOperationConfig
            {
                KeyExpression = new Expression
                {
                    ExpressionStatement = "Id = :userId AND begins_with(Meta, :role)",
                    ExpressionAttributeValues = new Dictionary<string, DynamoDBEntry>
                    {
                        {":userId", $"User#{user.Id}"},
                        {":role", "Role#" }
                    }
                }
            }, _dynamoConfig);

            var userRoles = await search.GetRemainingAsync(cancellationToken);

            if (userRoles.Count == 0)
            {
                return new List<string>();
            }

            var roleBatch = _context.CreateBatchGet<DynamoRole>(_dynamoConfig);
            foreach (var role in userRoles)
            {
                roleBatch.AddKey(role.RoleId, role.RoleId);
            }

            await roleBatch.ExecuteAsync(cancellationToken);

            return roleBatch.Results.Select(r => r.NormalizedName).Distinct().ToList();
        }

        public async Task<IList<DynamoUser>> GetUsersInRoleAsync(string normalisedRoleName, CancellationToken cancellationToken)
        {
            if (normalisedRoleName == null)
            {
                throw new ArgumentNullException(nameof(normalisedRoleName));
            }

            cancellationToken.ThrowIfCancellationRequested();

            var role = await _roleManager.FindByNameAsync(normalisedRoleName);

            if (role == null)
            {
                throw new ArgumentOutOfRangeException(nameof(normalisedRoleName));
            }

            var search = _context.FromQueryAsync<DynamoUserRole>(new QueryOperationConfig
            {
                IndexName = "MetaIndex",
                KeyExpression = new Expression
                {
                    ExpressionStatement = "Meta = :roleId AND begins_with(Id, :user)",
                    ExpressionAttributeValues = new Dictionary<string, DynamoDBEntry>
                    {
                        {":roleId", $"Role#{role.Id}"},
                        {":user", "User#" }
                    }
                }
            }, _dynamoConfig);

            var userRoles = await search.GetRemainingAsync(cancellationToken);

            if (userRoles.Count == 0)
            {
                return new List<DynamoUser>();
            }

            var userBatch = _context.CreateBatchGet<DynamoUser>(_dynamoConfig);
            foreach (var user in userRoles)
            {
                userBatch.AddKey(user.UserId, user.UserId);
            }

            await userBatch.ExecuteAsync(cancellationToken);

            return userBatch.Results;
        }

        public async Task<int> IncrementAccessFailedCountAsync(DynamoUser user, CancellationToken cancellationToken)
        {
            if (user == null)
            {
                throw new ArgumentNullException(nameof(user));
            }

            cancellationToken.ThrowIfCancellationRequested();

            user.AccessFailedCount += 1;

            return await Task.FromResult(user.AccessFailedCount);
        }

        public async Task AddClaimsAsync(DynamoUser user, IEnumerable<Claim> claims, CancellationToken cancellationToken)
        {
            if (user == null)
            {
                throw new ArgumentNullException(nameof(user));
            }

            if (claims == null)
            {
                throw new ArgumentNullException(nameof(claims));
            }

            var existingClaimsSearch = _context.FromQueryAsync<DynamoUserClaim>(new QueryOperationConfig
            {
                KeyExpression = new Expression
                {
                    ExpressionStatement = "Id = :userId AND begins_with(Meta, :claim)",
                    ExpressionAttributeValues = new Dictionary<string, DynamoDBEntry>
                    {
                        {":userId", $"User#{user.Id}"},
                        {":claim", "UserClaim#" }
                    }
                }
            }, _dynamoConfig);

            var existingClaims = await existingClaimsSearch.GetRemainingAsync(cancellationToken);

            var userClaimsBatch = _context.CreateBatchWrite<DynamoUserClaim>(_dynamoConfig);

            foreach (var claim in claims)
            {
                if (!existingClaims.Any(x => x.ClaimType == claim.Type && x.ClaimValue == claim.Value))
                {
                    var userClaim = new DynamoUserClaim()
                    {
                        UserId = user.Id,
                        ClaimType = claim.Type,
                        ClaimValue = claim.Value
                    };
                    userClaimsBatch.AddPutItem(userClaim);
                }
            }

            await userClaimsBatch.ExecuteAsync(cancellationToken);
        }

        public async Task<IList<Claim>> GetClaimsAsync(DynamoUser user, CancellationToken cancellationToken)
        {
            if (user == null)
            {
                throw new ArgumentNullException(nameof(user));
            }

            cancellationToken.ThrowIfCancellationRequested();

            var search = _context.FromQueryAsync<DynamoUserClaim>(new QueryOperationConfig
            {
                KeyExpression = new Expression
                {
                    ExpressionStatement = "Id = :userId AND begins_with(Meta, :claim)",
                    ExpressionAttributeValues = new Dictionary<string, DynamoDBEntry>
                    {
                        {":userId", $"User#{user.Id}"},
                        {":claim", "UserClaim#" }
                    }
                }
            }, _dynamoConfig);

            var userClaims = await search.GetRemainingAsync(cancellationToken);

            return userClaims.Select(x => new Claim(x.ClaimType, x.ClaimValue)).ToList();
        }

        public async Task<IList<DynamoUser>> GetUsersForClaimAsync(Claim claim, CancellationToken cancellationToken)
        {
            if (claim == null)
            {
                throw new ArgumentNullException(nameof(claim));
            }

            cancellationToken.ThrowIfCancellationRequested();

            var usersSearch = _context.ScanAsync<DynamoUserClaim>(new List<ScanCondition>
            {
                new ScanCondition("ClaimType", ScanOperator.Contains, claim.Type),
                new ScanCondition("ClaimValue", ScanOperator.Contains, claim.Value)
            }, _dynamoConfig);

            var users = (await usersSearch.GetRemainingAsync(cancellationToken)).Select(x => x.UserId).Distinct();

            var userBatch = _context.CreateBatchGet<DynamoUser>(_dynamoConfig);
            foreach (var user in users)
            {
                userBatch.AddKey(user, user);
            }

            await userBatch.ExecuteAsync(cancellationToken);

            return userBatch.Results;
        }

        public async Task ReplaceClaimAsync(DynamoUser user, Claim claim, Claim newClaim, CancellationToken cancellationToken)
        {
            if (user == null)
            {
                throw new ArgumentNullException(nameof(user));
            }

            if (claim == null)
            {
                throw new ArgumentNullException(nameof(claim));
            }

            if (newClaim == null)
            {
                throw new ArgumentNullException(nameof(newClaim));
            }

            var userClaimsSearch = _context.FromQueryAsync<DynamoUserClaim>(new QueryOperationConfig
            {
                KeyExpression = new Expression
                {
                    ExpressionStatement = "Id = :userId AND begins_with(Meta, :claim)",
                    ExpressionAttributeValues = new Dictionary<string, DynamoDBEntry>
                    {
                        {":userId", $"User#{user.Id}"},
                        {":claim", "UserClaim#" }
                    }
                }
            }, _dynamoConfig);

            var userClaims = await userClaimsSearch.GetRemainingAsync(cancellationToken);

            var oldUserClaim = userClaims.FirstOrDefault(x => x.ClaimType == claim.Type && x.ClaimValue == claim.Value);

            if (oldUserClaim == null)
            {
                throw new ArgumentOutOfRangeException(nameof(claim));
            }

            var newUserClaimExisting = userClaims.FirstOrDefault(x => x.ClaimType == newClaim.Type && x.ClaimValue == newClaim.Value);

            if (newUserClaimExisting != null)
            {
                throw new ArgumentException("New claim value already exists", nameof(newClaim));
            }

            var newUserClaim = new DynamoUserClaim()
            {
                UserId = user.Id,
                ClaimType = newClaim.Type,
                ClaimValue = newClaim.Value
            };

            await _context.DeleteAsync(oldUserClaim, _dynamoConfig, cancellationToken);
            await _context.SaveAsync(newUserClaim, _dynamoConfig, cancellationToken);
        }

        public async Task RemoveClaimsAsync(DynamoUser user, IEnumerable<Claim> claims, CancellationToken cancellationToken)
        {
            if (user == null)
            {
                throw new ArgumentNullException(nameof(user));
            }

            if (claims == null)
            {
                throw new ArgumentNullException(nameof(claims));
            }

            var userClaimsSearch = _context.FromQueryAsync<DynamoUserClaim>(new QueryOperationConfig
            {
                KeyExpression = new Expression
                {
                    ExpressionStatement = "Id = :userId AND begins_with(Meta, :claim)",
                    ExpressionAttributeValues = new Dictionary<string, DynamoDBEntry>
                    {
                        {":userId", $"User#{user.Id}"},
                        {":claim", "UserClaim#" }
                    }
                }
            }, _dynamoConfig);

            var userClaims = await userClaimsSearch.GetRemainingAsync(cancellationToken);
            var userClaimsBatch = _context.CreateBatchWrite<DynamoUserClaim>(_dynamoConfig);

            foreach (var claim in claims)
            {
                var claimToRemove = userClaims.FirstOrDefault(x => x.ClaimType == claim.Type && x.ClaimValue == claim.Value);
                if (claimToRemove != null)
                {
                    userClaimsBatch.AddDeleteItem(claimToRemove);
                }
            }

            await userClaimsBatch.ExecuteAsync(cancellationToken);
        }

        public async Task<DynamoUser> FindByLoginAsync(string loginProvider, string providerKey, CancellationToken cancellationToken)
        {
            if (loginProvider == null)
            {
                throw new ArgumentNullException(nameof(loginProvider));
            }

            if (providerKey == null)
            {
                throw new ArgumentNullException(nameof(providerKey));
            }

            cancellationToken.ThrowIfCancellationRequested();

            var existingLoginProviderSearch = _context.FromQueryAsync<DynamoUserLogin>(new QueryOperationConfig
            {
                IndexName = "LoginProviderIndex",
                KeyExpression = new Expression
                {
                    ExpressionStatement = "Meta = :providerKey AND LoginProvider = :loginProvider",
                    ExpressionAttributeValues = new Dictionary<string, DynamoDBEntry>
                    {
                        {":providerKey", $"UserLogin#{providerKey}" },
                        {":loginProvider", loginProvider }
                    }
                },
                Limit = 1
            }, _dynamoConfig);

            var existingLoginProvider = (await existingLoginProviderSearch.GetRemainingAsync(cancellationToken)).FirstOrDefault();

            if (existingLoginProvider == null)
            {
                return null;
            }

            var user = await _context.LoadAsync<DynamoUser>(existingLoginProvider.UserId, existingLoginProvider.UserId, _dynamoConfig, cancellationToken);
            return user;
        }

        public async Task AddLoginAsync(DynamoUser user, UserLoginInfo login, CancellationToken cancellationToken)
        {
            if (user == null)
            {
                throw new ArgumentNullException(nameof(user));
            }

            if (login == null)
            {
                throw new ArgumentNullException(nameof(login));
            }

            cancellationToken.ThrowIfCancellationRequested();

            var userlogin = new DynamoUserLogin()
            {
                LoginProvider = login.LoginProvider,
                ProviderDisplayName = login.ProviderDisplayName,
                UserId = user.Id,
                ProviderKey = login.ProviderKey
            };

            await _context.SaveAsync(userlogin, _dynamoConfig, cancellationToken);
        }

        public async Task<IList<UserLoginInfo>> GetLoginsAsync(DynamoUser user, CancellationToken cancellationToken)
        {
            if (user == null)
            {
                throw new ArgumentNullException(nameof(user));
            }

            cancellationToken.ThrowIfCancellationRequested();

            var search = _context.FromQueryAsync<DynamoUserLogin>(new QueryOperationConfig
            {
                KeyExpression = new Expression
                {
                    ExpressionStatement = "Id = :userId AND begins_with(Meta, :login)",
                    ExpressionAttributeValues = new Dictionary<string, DynamoDBEntry>
                    {
                        {":userId", $"User#{user.Id}"},
                        {":login", "UserLogin#" }
                    }
                }
            }, _dynamoConfig);

            var userLogins = await search.GetRemainingAsync(cancellationToken);

            return userLogins.Select(x => new UserLoginInfo(x.LoginProvider, x.LoginProvider, x.ProviderDisplayName)).ToList();
        }

        public async Task RemoveLoginAsync(DynamoUser user, string loginProvider, string providerKey, CancellationToken cancellationToken)
        {
            if (user == null)
            {
                throw new ArgumentNullException(nameof(user));
            }

            if (loginProvider == null)
            {
                throw new ArgumentNullException(nameof(loginProvider));
            }

            if (providerKey == null)
            {
                throw new ArgumentNullException(nameof(providerKey));
            }

            var existingLoginProviderSearch = _context.FromQueryAsync<DynamoUserLogin>(new QueryOperationConfig
            {
                IndexName = "LoginProviderIndex",
                KeyExpression = new Expression
                {
                    ExpressionStatement = "Meta = :providerKey AND LoginProvider = :loginProvider",
                    ExpressionAttributeValues = new Dictionary<string, DynamoDBEntry>
                    {
                        {":providerKey", $"UserLogin#{providerKey}" },
                        {":loginProvider", loginProvider }
                    }
                },
                Limit = 1
            }, _dynamoConfig);

            var existingLoginProvider = (await existingLoginProviderSearch.GetRemainingAsync(cancellationToken)).FirstOrDefault();

            if (existingLoginProvider.UserId != user.Id)
            {
                throw new ArgumentOutOfRangeException(nameof(loginProvider));
            }

            await _context.DeleteAsync(existingLoginProvider, _dynamoConfig, cancellationToken);
        }

        public async Task SetTokenAsync(DynamoUser user, string loginProvider, string name, string value, CancellationToken cancellationToken)
        {
            if (user == null)
            {
                throw new ArgumentNullException(nameof(user));
            }

            if (loginProvider == null)
            {
                throw new ArgumentNullException(nameof(loginProvider));
            }

            if (name == null)
            {
                throw new ArgumentNullException(nameof(name));
            }

            if (value == null)
            {
                throw new ArgumentNullException(nameof(value));
            }

            cancellationToken.ThrowIfCancellationRequested();

            var userToken = new DynamoUserToken()
            {
                LoginProvider = loginProvider,
                Name = name,
                UserId = user.Id,
                Value = value
            };

            await _context.SaveAsync(userToken, _dynamoConfig, cancellationToken);
        }

        public async Task<string> GetTokenAsync(DynamoUser user, string loginProvider, string name, CancellationToken cancellationToken)
        {
            if (user == null)
            {
                throw new ArgumentNullException(nameof(user));
            }

            if (loginProvider == null)
            {
                throw new ArgumentNullException(nameof(loginProvider));
            }

            if (name == null)
            {
                throw new ArgumentNullException(nameof(name));
            }

            cancellationToken.ThrowIfCancellationRequested();

            var search = _context.FromQueryAsync<DynamoUserToken>(new QueryOperationConfig
            {
                KeyExpression = new Expression
                {
                    ExpressionStatement = "Id = :userId AND begins_with(Meta, :token)",
                    ExpressionAttributeValues = new Dictionary<string, DynamoDBEntry>
                    {
                        {":userId", $"User#{user.Id}"},
                        {":token", "UserToken#" }
                    }
                },
                FilterExpression = new Expression
                {
                    ExpressionStatement = "LoginProvider = :loginProvider AND TokenName = :tokenname",
                    ExpressionAttributeValues = new Dictionary<string, DynamoDBEntry>
                    {
                        {":loginProvider", loginProvider},
                        {":tokenname", name }
                    }
                },
                Limit = 1
            }, _dynamoConfig);

            var userToken = (await search.GetRemainingAsync(cancellationToken)).FirstOrDefault();

            return userToken.Value;
        }

        public async Task RemoveTokenAsync(DynamoUser user, string loginProvider, string name, CancellationToken cancellationToken)
        {
            if (user == null)
            {
                throw new ArgumentNullException(nameof(user));
            }

            if (loginProvider == null)
            {
                throw new ArgumentNullException(nameof(loginProvider));
            }

            if (name == null)
            {
                throw new ArgumentNullException(nameof(name));
            }

            var search = _context.FromQueryAsync<DynamoUserToken>(new QueryOperationConfig
            {
                KeyExpression = new Expression
                {
                    ExpressionStatement = "Id = :userId AND begins_with(Meta, :token)",
                    ExpressionAttributeValues = new Dictionary<string, DynamoDBEntry>
                    {
                        {":userId", $"User#{user.Id}"},
                        {":token", "UserToken#" }
                    }
                },
                FilterExpression = new Expression
                {
                    ExpressionStatement = "LoginProvider = :loginProvider AND TokenName = :tokenname",
                    ExpressionAttributeValues = new Dictionary<string, DynamoDBEntry>
                    {
                        {":loginProvider", loginProvider},
                        {":tokenname", name }
                    }
                },
                Limit = 1
            }, _dynamoConfig);

            var userToken = (await search.GetRemainingAsync(cancellationToken)).FirstOrDefault();

            if (userToken != null)
            {
                await _context.DeleteAsync(userToken, _dynamoConfig, cancellationToken);
            }
        }

        public Task SetAuthenticatorKeyAsync(DynamoUser user, string key, CancellationToken cancellationToken)
        {
            return SetTokenAsync(user, AuthenticatorStoreLoginProvider, AuthenticatorKeyTokenName, key, cancellationToken);
        }

        public Task<string> GetAuthenticatorKeyAsync(DynamoUser user, CancellationToken cancellationToken)
        {
            return GetTokenAsync(user, AuthenticatorStoreLoginProvider, AuthenticatorKeyTokenName, cancellationToken);
        }

        public Task ReplaceCodesAsync(DynamoUser user, IEnumerable<string> recoveryCodes, CancellationToken cancellationToken)
        {
            var mergedCodes = string.Join(";", recoveryCodes);
            return SetTokenAsync(user, AuthenticatorStoreLoginProvider, RecoveryCodeTokenName, mergedCodes, cancellationToken);
        }

        public async Task<bool> RedeemCodeAsync(DynamoUser user, string code, CancellationToken cancellationToken)
        {
            var mergedCodes = await GetTokenAsync(user, AuthenticatorStoreLoginProvider, RecoveryCodeTokenName, cancellationToken) ?? "";
            var splitCodes = mergedCodes.Split(';');
            if (splitCodes.Contains(code))
            {
                var updatedCodes = new List<string>(splitCodes.Where(s => s != code));
                await ReplaceCodesAsync(user, updatedCodes, cancellationToken);
                return true;
            }
            return false;
        }

        public async Task<int> CountCodesAsync(DynamoUser user, CancellationToken cancellationToken)
        {
            var mergedCodes = await GetTokenAsync(user, AuthenticatorStoreLoginProvider, RecoveryCodeTokenName, cancellationToken) ?? "";
            if (mergedCodes.Length > 0)
            {
                return mergedCodes.Split(';').Length;
            }
            return 0;
        }

        public async Task<IdentityResult> DeleteAsync(DynamoUser user, CancellationToken cancellationToken)
        {
            if (user == null)
            {
                throw new ArgumentNullException(nameof(user));
            }

            cancellationToken.ThrowIfCancellationRequested();

            var userToDelete = await _context.LoadAsync<DynamoUser>(user.Id, user.Id, _dynamoConfig, cancellationToken);
            var userBatch = _context.CreateBatchWrite<DynamoUser>(new DynamoDBOperationConfig() { OverrideTableName = _options.DynamoTableName, SkipVersionCheck = true });
            userBatch.AddDeleteItem(userToDelete);

            var userClaims = await _context.FromQueryAsync<DynamoUserClaim>(new QueryOperationConfig()
            {
                KeyExpression = new Expression()
                {
                    ExpressionStatement = "Id = :userId AND begins_with(Meta, :claim)",
                    ExpressionAttributeValues = new Dictionary<string, DynamoDBEntry>
                    {
                        {":userId", $"User#{user.Id}"},
                        {":claim", "UserClaim#" }
                    }
                }
            }, _dynamoConfig).GetRemainingAsync(cancellationToken);

            var userClaimsBatch = _context.CreateBatchWrite<DynamoUserClaim>(_dynamoConfig);
            foreach (var item in userClaims)
            {
                userClaimsBatch.AddDeleteItem(item);
            }

            var userRoles = await _context.FromQueryAsync<DynamoUserRole>(new QueryOperationConfig()
            {
                KeyExpression = new Expression()
                {
                    ExpressionStatement = "Id = :userId AND begins_with(Meta, :role)",
                    ExpressionAttributeValues = new Dictionary<string, DynamoDBEntry>
                    {
                        {":userId", $"User#{user.Id}"},
                        {":role", "Role#" }
                    }
                }
            }, _dynamoConfig).GetRemainingAsync(cancellationToken);

            var userRolesBatch = _context.CreateBatchWrite<DynamoUserRole>(_dynamoConfig);
            foreach (var item in userRoles)
            {
                userRolesBatch.AddDeleteItem(item);
            }

            var userTokens = await _context.FromQueryAsync<DynamoUserToken>(new QueryOperationConfig()
            {
                KeyExpression = new Expression()
                {
                    ExpressionStatement = "Id = :userId AND begins_with(Meta, :token)",
                    ExpressionAttributeValues = new Dictionary<string, DynamoDBEntry>
                    {
                        {":userId", $"User#{user.Id}"},
                        {":token", "UserToken#" }
                    }
                }
            }, _dynamoConfig).GetRemainingAsync(cancellationToken);

            var userTokensBatch = _context.CreateBatchWrite<DynamoUserToken>(_dynamoConfig);
            foreach (var item in userTokens)
            {
                userTokensBatch.AddDeleteItem(item);
            }

            var userLogins = await _context.FromQueryAsync<DynamoUserLogin>(new QueryOperationConfig()
            {
                KeyExpression = new Expression()
                {
                    ExpressionStatement = "Id = :userId AND begins_with(Meta, :login)",
                    ExpressionAttributeValues = new Dictionary<string, DynamoDBEntry>
                    {
                        {":userId", $"User#{user.Id}"},
                        {":login", "UserLogin#" }
                    }
                }
            }, _dynamoConfig).GetRemainingAsync(cancellationToken);

            var userLoginsBatch = _context.CreateBatchWrite<DynamoUserLogin>(_dynamoConfig);
            foreach (var item in userLogins)
            {
                userLoginsBatch.AddDeleteItem(item);
            }

            var batch = userBatch.Combine(userRolesBatch, userClaimsBatch, userLoginsBatch, userTokensBatch);

            await batch.ExecuteAsync(cancellationToken);

            return IdentityResult.Success;
        }

#pragma warning disable CA1816 // Dispose methods should call SuppressFinalize
        public void Dispose() { }
#pragma warning restore CA1816 // Dispose methods should call SuppressFinalize
    }
}
