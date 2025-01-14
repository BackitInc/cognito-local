import {
  AdminInitiateAuthRequest,
  AdminInitiateAuthResponse,
} from "aws-sdk/clients/cognitoidentityserviceprovider";
import {
  InvalidParameterError,
  InvalidPasswordError,
  NotAuthorizedError,
  UnsupportedError,
  UserNotConfirmedException,
} from "../errors";
import { Services } from "../services";
import { Target } from "./Target";
import { Context } from "../services/context";

export type AdminInitiateAuthTarget = Target<
  AdminInitiateAuthRequest,
  AdminInitiateAuthResponse
>;

type AdminInitiateAuthServices = Pick<
  Services,
  "cognito" | "triggers" | "tokenGenerator"
>;

const adminNoSrpAuthFlow = async (
  ctx: Context,
  services: AdminInitiateAuthServices,
  req: AdminInitiateAuthRequest
): Promise<AdminInitiateAuthResponse> => {
  // Validate required parameters
  if (!req.AuthParameters) {
    throw new InvalidParameterError(
      "Missing required parameter AuthParameters"
    );
  }

  const username = req.AuthParameters.USERNAME;

  if (!username) {
    throw new InvalidParameterError("AuthParameters USERNAME is required");
  }

  // Get the user pool and client
  const userPool = await services.cognito.getUserPoolForClientId(
    ctx,
    req.ClientId
  );
  const userPoolClient = await services.cognito.getAppClient(ctx, req.ClientId);

  if (!userPool || !userPoolClient) {
    throw new NotAuthorizedError();
  }

  // Find the user in the user pool
  const user = await userPool.getUserByUsername(ctx, username);
  if (!user) {
    throw new NotAuthorizedError();
  }

  // Check if the user is unconfirmed
  if (user.UserStatus === "UNCONFIRMED") {
    throw new UserNotConfirmedException();
  }

  // Retrieve the user's groups
  const userGroups = await userPool.listUserGroupMembership(ctx, user);

  // Generate authentication tokens
  const tokens = await services.tokenGenerator.generate(
    ctx,
    user,
    userGroups,
    userPoolClient,
    req.ClientMetadata,
    "Authentication"
  );

  // Store the refresh token
  await userPool.storeRefreshToken(ctx, tokens.RefreshToken || "", user);

  // Return the authentication result
  return {
    ChallengeName: undefined,
    Session: undefined,
    ChallengeParameters: undefined,
    AuthenticationResult: {
      AccessToken: tokens.AccessToken,
      RefreshToken: tokens.RefreshToken,
      IdToken: tokens.IdToken,
      NewDeviceMetadata: undefined,
      TokenType: "Bearer",
      ExpiresIn: 3600, // Tokens are valid for 1 hour
    },
  };
};

const adminUserPasswordAuthFlow = async (
  ctx: Context,
  services: AdminInitiateAuthServices,
  req: AdminInitiateAuthRequest
): Promise<AdminInitiateAuthResponse> => {
  if (!req.AuthParameters) {
    throw new InvalidParameterError(
      "Missing required parameter authParameters"
    );
  }

  if (!req.AuthParameters.USERNAME || !req.AuthParameters.PASSWORD) {
    throw new InvalidParameterError(
      "AuthParameters USERNAME and PASSWORD are required"
    );
  }

  const userPool = await services.cognito.getUserPoolForClientId(
    ctx,
    req.ClientId
  );
  const userPoolClient = await services.cognito.getAppClient(ctx, req.ClientId);
  let user = await userPool.getUserByUsername(ctx, req.AuthParameters.USERNAME);

  if (!user && services.triggers.enabled("UserMigration")) {
    // https://docs.aws.amazon.com/cognito/latest/developerguide/user-pool-lambda-migrate-user.html
    //
    // Amazon Cognito invokes [the User Migration] trigger when a user does not exist in the user pool at the time of
    // sign-in with a password, or in the forgot-password flow. After the Lambda function returns successfully, Amazon
    // Cognito creates the user in the user pool.
    user = await services.triggers.userMigration(ctx, {
      clientMetadata: {},
      validationData: {},
      userPoolId: userPool.options.Id,
      clientId: req.ClientId,
      username: req.AuthParameters.USERNAME,
      password: req.AuthParameters.PASSWORD,
      userAttributes: [],
    });
  }

  if (!user || !userPoolClient) {
    throw new NotAuthorizedError();
  }

  if (user.Password !== req.AuthParameters.PASSWORD) {
    throw new InvalidPasswordError();
  }

  if (user.UserStatus === "UNCONFIRMED") {
    throw new UserNotConfirmedException();
  }

  const userGroups = await userPool.listUserGroupMembership(ctx, user);

  const tokens = await services.tokenGenerator.generate(
    ctx,
    user,
    userGroups,
    userPoolClient,
    req.ClientMetadata,
    "Authentication"
  );

  await userPool.storeRefreshToken(ctx, tokens.RefreshToken || "", user);

  return {
    ChallengeName: undefined,
    Session: undefined,
    ChallengeParameters: undefined,
    AuthenticationResult: {
      AccessToken: tokens.AccessToken,
      RefreshToken: tokens.RefreshToken,
      IdToken: tokens.IdToken,
      NewDeviceMetadata: undefined,
      TokenType: undefined,
      ExpiresIn: undefined,
    },
  };
};

const refreshTokenAuthFlow = async (
  ctx: Context,
  services: AdminInitiateAuthServices,
  req: AdminInitiateAuthRequest
): Promise<AdminInitiateAuthResponse> => {
  if (!req.AuthParameters) {
    throw new InvalidParameterError(
      "Missing required parameter authParameters"
    );
  }

  if (!req.AuthParameters.REFRESH_TOKEN) {
    throw new InvalidParameterError("AuthParameters REFRESH_TOKEN is required");
  }

  const userPool = await services.cognito.getUserPoolForClientId(
    ctx,
    req.ClientId
  );
  const userPoolClient = await services.cognito.getAppClient(ctx, req.ClientId);
  const user = await userPool.getUserByRefreshToken(
    ctx,
    req.AuthParameters.REFRESH_TOKEN
  );
  if (!user || !userPoolClient) {
    throw new NotAuthorizedError();
  }

  const userGroups = await userPool.listUserGroupMembership(ctx, user);

  const tokens = await services.tokenGenerator.generate(
    ctx,
    user,
    userGroups,
    userPoolClient,
    req.ClientMetadata,
    "RefreshTokens"
  );

  return {
    ChallengeName: undefined,
    Session: undefined,
    ChallengeParameters: undefined,
    AuthenticationResult: {
      AccessToken: tokens.AccessToken,
      RefreshToken: undefined,
      IdToken: tokens.IdToken,
      NewDeviceMetadata: undefined,
      TokenType: undefined,
      ExpiresIn: undefined,
    },
  };
};

export const AdminInitiateAuth =
  (services: AdminInitiateAuthServices): AdminInitiateAuthTarget =>
  async (ctx, req) => {
    if (req.AuthFlow === "ADMIN_USER_PASSWORD_AUTH") {
      return adminUserPasswordAuthFlow(ctx, services, req);
    } else if (req.AuthFlow === "ADMIN_NO_SRP_AUTH") {
      return adminNoSrpAuthFlow(ctx, services, req);
    } else if (
      req.AuthFlow === "REFRESH_TOKEN_AUTH" ||
      req.AuthFlow === "REFRESH_TOKEN"
    ) {
      return refreshTokenAuthFlow(ctx, services, req);
    } else {
      throw new UnsupportedError(`AdminInitAuth with AuthFlow=${req.AuthFlow}`);
    }
  };
