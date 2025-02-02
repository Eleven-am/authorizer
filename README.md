# Authorizer

A powerful, type-safe authorization package for NestJS applications that combines CASL's flexibility with TypeScript and NestJS decorators. Supports both HTTP and [PondSocket](https://github.com/Eleven-am/pondSocket) contexts out of the box.

## Features

- 🔒 Type-safe permission definitions with Prisma integration
- 🚀 Built-in support for HTTP and PondSocket
- 📝 Field-level permissions
- 🎯 Seamless NestJS integration
- 🔍 Automatic Prisma query filtering with CASL
- ⚡ Decorator-based permission checks
- 🎨 Declarative authorization rules

## Why Use Authorizers?

Traditional authorization approaches often scatter access control logic across services and controllers, leading to:
- Duplicated authorization checks
- Inconsistent rule enforcement
- Mixed business and authorization logic
- Maintenance difficulties
- Potential security holes

Authorizers solve these problems by:
- Centralizing authorization logic
- Providing type-safe permission definitions
- Enforcing permissions at the database level
- Creating clear boundaries between business and authorization logic
- Enabling easy testing and maintenance

## Installation

```bash
npm install @eleven-am/authorizer
```

## Initial Setup

### 1. Configure Root Module

The `AuthorizationModule` **must** be imported in your root `AppModule`. This is crucial as it provides the `AuthorizationService` to the guards in your feature modules.

```typescript
import { AuthorizationModule } from '@eleven-am/authorizer';
import { APP_GUARD } from '@nestjs/core';
import { AuthHttpGuard, AuthSocketGuard } from './auth.guard';
import { UserModule } from './user.module';
import { PostModule } from './post.module';
import { PondSocketModule } from '@eleven-am/pondsocket-nest';
import { Module } from '@nestjs/common';

@Module({
  imports: [
    // Import AuthorizationModule at the root level to provide AuthorizationService globally
    AuthorizationModule,
          
    // Import PondSocketModule with AuthSocketGuard
    PondSocketModule.forRoot({
       guards: [AuthSocketGuard]
    }),
    
    // Your feature modules can then use AuthorizationService
    UserModule,
    PostModule,
  ],
  providers: [
     {
        provide: APP_GUARD,
        // Use AuthHttpGuard for all HTTP routes
        useClass: AuthHttpGuard
     }
  ]
})
export class AppModule {}

// Feature modules don't need to import AuthorizationModule again
@Module({
  imports: [],  // NOT AuthorizationModule - it's already provided by root
  providers: [
    PostService,
    PostAuthorizer,
    AuthHttpGuard
  ],
  controllers: [PostController]
})
export class PostModule {}
```

### 2. Define Your Prisma Types

```typescript
import {
    User as ModelUser,
    Post,
    Comment,
    // ... other Prisma models
} from '@prisma/client';

// Extend the package's types with your Prisma models
declare module '@eleven-am/authorizer' {
    interface SubjectTypes {
        User: ModelUser;
        Post: Post;
        Comment: Comment;
        // ... other models
    }

    // Define the User type for the package
    interface User extends ModelUser {}
}
```

### 3. Create Authorization Guard

```typescript
import { AuthorizationService } from '@eleven-am/authorizer';
import { TaskEither } from '@eleven-am/fp';
import { CanActivate, ExecutionContext, Injectable } from '@nestjs/common';

@Injectable()
export class AuthHttpGuard implements CanActivate {
    constructor(
        protected readonly sessionService: SessionService,
        protected readonly authorizationService: AuthorizationService,
    ) {}

    canActivate(context: ExecutionContext) {
        const task = this.getSession(context)
            .map((session) => session?.user ?? null)
            .chain((user) => this.authorizationService.checkHttpAction(user, context));

        return mapTaskEither(task);
    }

    private getSession(context: ExecutionContext) {
        const request = context.switchToHttp().getRequest<Request>();
        const token = this.extractToken(request);
        
        return TaskEither
            .fromNullable(token)
            .chain((token) => this.sessionService.readSession(token))
            .orElse(() => TaskEither.of(null))
            .ioSync((session) => {
                request.session = session;
            });
    }
}
```

### 4. Create Your Authorizer

```typescript
@Authorizer()
class PostAuthorizer implements WillAuthorize {
  forUser(user: User, builder: RuleBuilder): void {
    if (user.role === 'admin') {
      builder.can(Action.Manage, 'Post');
      builder.can(Action.Manage, 'Comment');
    } else {
      builder.can(Action.Read, 'Post');
      builder.can(Action.Create, 'Post');
      builder.can(Action.Update, 'Post', { authorId: user.id });
      builder.can(Action.Delete, 'Post', { authorId: user.id });
    }
  }
}
```

### 5. Set Up Feature Module

Once `AuthorizationModule` is imported in the root module, your feature modules can use the `AuthorizationService` without additional imports:

```typescript
@Module({
  providers: [
    PostService,
    PostAuthorizer,    // Your custom authorizer
    PrismaService
  ],
  controllers: [PostController]
})
export class PostModule {}
```

## Usage

### HTTP Controllers

```typescript
@UseGuards(AuthHttpGuard)
@Controller('posts')
export class PostController {
  constructor(private postService: PostService) {}

  @Get()
  @CanPerform({ action: Action.Read, resource: 'Post' })
  async getAllPosts(@CurrentAbility.HTTP() ability: AppAbilityType) {
    return this.postService.findAll(ability);
  }

  @Patch(':id')
  @CanPerform({ 
    action: Action.Update, 
    resource: 'Post',
    field: 'content'
  })
  async updatePost(
    @Param('id') id: number,
    @Body() data: UpdatePostDto,
    @CurrentAbility.HTTP() ability: AppAbilityType
  ) {
    return this.postService.update(id, data, ability);
  }
}
```

### PondSocket Integration

This package is specifically designed to work with [PondSocket](https://github.com/Eleven-am/pondSocket) for WebSocket support:

```typescript
@UseGuards(AuthWsGuard)
@Channel('posts')
export class PostChannel {
  @OnMessage('find-all')
  @CanPerform({ action: Action.Read, resource: 'Post' })
  async findAll(@CurrentAbility.WS() ability: AppAbilityType) {
    return this.postService.findAll(ability);
  }
}
```

### Services with CASL Integration

```typescript
@Injectable()
export class PostService {
  constructor(private prisma: PrismaService) {}

  async findAll(ability: AppAbilityType) {
    return this.prisma.post.findMany({
      where: accessibleBy(ability).Post
    });
  }

  async findWithComments(ability: AppAbilityType) {
    return this.prisma.post.findMany({
      where: accessibleBy(ability).Post,
      include: {
        comments: {
          where: accessibleBy(ability).Comment
        }
      }
    });
  }

  async update(id: number, data: UpdatePostDto, ability: AppAbilityType) {
    const post = await this.prisma.post.findUnique({ where: { id } });
    if (!post) throw new NotFoundException();

    if (ability.can(Action.Update, post)) {
      return this.prisma.post.update({
        where: { id },
        data
      });
    }
    
    throw new ForbiddenException();
  }
}
```

## Key Concepts

### Guards and Authorization Flow

1. Request arrives
2. Guard extracts user session
3. AuthorizationService checks permissions
4. If authorized:
    - Handler executes
    - Service can assume authorization is handled
5. If unauthorized:
    - Request is rejected immediately
    - No business logic executes

### Authorizers

Authorizers are NestJS providers that:
- Define all permission rules in one place
- Support dependency injection
- Can be combined for complex scenarios
- Keep authorization logic isolated

### Database Integration

The package integrates with Prisma through CASL:
- Automatically filters queries based on permissions
- Supports relations and complex queries
- Prevents N+1 query problems
- Maintains consistent access control

## Advanced Usage

### Field-Level Permissions

```typescript
@CanPerform({ 
  action: Action.Update, 
  resource: 'Post',
  field: 'title'
})
```

### Complex Queries

```typescript
export class PostService {
  async findWithComments(ability: AppAbilityType) {
    return this.prisma.post.findMany({
      where: accessibleBy(ability).Post,
      include: {
        comments: {
          where: accessibleBy(ability).Comment
        }
      }
    });
  }
}
```

### Custom Authorization Logic

```typescript
@Authorizer()
class CustomAuthorizer implements WillAuthorize {
  forUser(user: User, builder: RuleBuilder): void {
    // Define basic rules
  }

  checkHttpAction(
    ability: AppAbilityType, 
    rules: Permission[], 
    context: ExecutionContext
  ): TaskEither<boolean> {
    // Custom HTTP authorization logic
    return TaskEither.right(true);
  }
}
```

## API Reference

### Decorators
- `@Authorizer()`: Marks a class as an authorizer
- `@CanPerform()`: Checks permissions for routes/handlers
- `@CurrentAbility`: Injects the current ability object

### Interfaces
- `WillAuthorize`: For creating authorizers
- `Permission`: Defines individual permissions
- `RuleBuilder`: For building CASL rules

### Services
- `AuthorizationService`: Core service for checking permissions. It should be used in guards to authorize requests before they reach controllers/services.

## Requirements

- NestJS 8.0 or higher
- PondSocket (for WebSocket support)
- TypeScript 4.7 or higher

## License

[MIT License](LICENSE)

## Credits

Built with:
- [NestJS](https://nestjs.com/)
- [CASL](https://casl.js.org/)
- [@casl/prisma](https://github.com/stalniy/casl/tree/master/packages/casl-prisma)
- [PondSocket](https://github.com/Eleven-am/pondSocket)
