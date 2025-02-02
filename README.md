# Authorizer

A powerful, type-safe authorization package for NestJS applications that combines the flexibility of CASL with the power of TypeScript and NestJS decorators. Supports both HTTP and WebSocket contexts out of the box.

## Features

- 🔒 Type-safe permission definitions
- 🚀 Support for both HTTP and WebSocket contexts
- 📝 Field-level permissions
- 🎯 Easy integration with NestJS
- 🔍 Prisma query integration
- ⚡ Decorator-based permission checks
- 🎨 Flexible rule definitions

## Installation

```bash
npm install @eleven-am/authorizer
```

## Quick Start

### 1. Define Your Subject Types

First, import your Prisma types and extend the package's interfaces. Create a `types.ts` file:

```typescript
import {
    User as ModelUser,
    Post,
    Comment,
    // ... other Prisma models
} from '@prisma/client';

// Extend the package's types to include your Prisma models
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

This ensures type safety with your Prisma models.

### 3. Create an Authorizer

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

### 4. Create Your Service

```typescript
@Injectable()
export class PostService {
  constructor(
    private prisma: PrismaService,
    private authService: AuthorizationService
  ) {}

  async findAll(ability: AppAbilityType) {
    // The ability can be used to filter queries
    return this.prisma.post.findMany({ 
        where: accessibleBy(ability).Post 
    });
  }

  async update(id: number, data: UpdatePostDto, ability: AppAbilityType) {
    const post = await this.prisma.post.findUnique({ where: { id } });
    if (!post) throw new NotFoundException();

    // You can use the ability to check permissions programmatically
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

### 5. Set Up Your Module

```typescript
@Module({
  imports: [AuthorizationModule],
  providers: [
    PostService,
    PostAuthorizer, // Authorizer is just another provider
    PrismaService
  ],
  controllers: [PostController]
})
export class AppModule {}
```

### 6. Use in Controllers

```typescript
@Controller('posts')
export class PostController {
  @Get()
  @CanPerform({ action: Action.Read, resource: 'Post' })
  async getAllPosts(@CurrentAbility.HTTP() ability: AppAbilityType) {
    return this.postService.findAll();
  }

  @Patch(':id')
  @CanPerform({ 
    action: Action.Update, 
    resource: 'Post',
    field: 'content'
  })
  async updatePost(
    @Param('id') id: number,
    @Body() data: UpdatePostDto
  ) {
    return this.postService.update(id, data);
  }
}
```

## WebSocket Support

The package provides built-in support for PondSocket, a WebSocket library for NestJS. You can use the `@CurrentAbility.WS()` decorator to access the user's ability in WebSocket gateways:

```typescript
@Channel('posts')
export class PostEndpoint {
  @OnMessage('find-all')
  @CanPerform({ action: Action.Read, resource: 'Post' })
  async findAll(@CurrentAbility.WS() ability: AppAbilityType) {
    // Handle WebSocket message
  }
}
```

## Understanding Authorizers

Authorizers in this package are simply NestJS providers that implement the `WillAuthorize` interface. They serve as a clean way to organize your authorization logic and can be injected anywhere in your application like any other provider.

Key points about authorizers:
- They are regular NestJS providers decorated with `@Authorizer()`
- They can be injected into services and other providers
- Multiple authorizers can coexist in your application
- They can use dependency injection to access your services and repositories

## Advanced Usage

### Field-Level Permissions

You can specify permissions for specific fields:

```typescript
@CanPerform({ 
  action: Action.Update, 
  resource: 'Post',
  field: 'title'
})
```

### Custom Authorization Logic

Implement custom authorization logic by extending the `checkHttpAction` or `checkSocketAction` methods:

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
    // Implement custom HTTP authorization logic
    return TaskEither.right(true);
  }
}
```

### Using with Prisma and CASL's accessibleBy

The package integrates seamlessly with Prisma through `@casl/prisma`. Here's how to use it with CASL's `accessibleBy`:

```typescript
import { accessibleBy } from '@casl/prisma';
import { Injectable } from '@nestjs/common';
import { Prisma } from '@prisma/client';

@Injectable()
export class PostService {
  constructor(private prisma: PrismaService) {}

  // Using with findMany
  async findAll(ability: AppAbilityType) {
    return this.prisma.post.findMany({
      where: accessibleBy(ability).Post,
    });
  }

  // Using with findFirst
  async findOne(id: number, ability: AppAbilityType) {
    return this.prisma.post.findFirst({
      where: {
        id,
        AND: accessibleBy(ability).Post,
      },
    });
  }

  // Combining with other Prisma conditions
  async findFiltered(
    ability: AppAbilityType,
    filters: Prisma.PostWhereInput
  ) {
    return this.prisma.post.findMany({
      where: {
        AND: [
          filters,
          accessibleBy(ability).Post,
        ],
      },
    });
  }

  // Using with relations
  async findWithComments(ability: AppAbilityType) {
    return this.prisma.post.findMany({
      where: accessibleBy(ability).Post,
      include: {
        comments: {
          where: accessibleBy(ability).Comment,
        },
      },
    });
  }
}

// In your controller
@Controller('posts')
export class PostController {
  constructor(private postService: PostService) {}

  @Get()
  @CanPerform({ action: Action.Read, resource: 'Post' })
  async getAllPosts(@CurrentAbility.HTTP() ability: AppAbilityType) {
    return this.postService.findAll(ability);
  }

  @Get(':id')
  @CanPerform({ action: Action.Read, resource: 'Post' })
  async getPost(
    @Param('id') id: number,
    @CurrentAbility.HTTP() ability: AppAbilityType
  ) {
    const post = await this.postService.findOne(id, ability);
    if (!post) throw new NotFoundException();
    return post;
  }
}
```

The `accessibleBy` function automatically converts CASL abilities into Prisma queries, ensuring that users can only access records they're authorized to see. This provides a robust way to filter data at the database level based on your authorization rules.

## API Reference

### Decorators

- `@Authorizer()`: Marks a class as an authorizer
- `@CanPerform()`: Checks if the user can perform specific actions
- `@CurrentAbility`: Injects the current user's ability
- `createParamDecorator`: Creates custom decorators for extracting data from the request context and socket connection

### Interfaces

- `WillAuthorize`: Interface for defining authorization rules
- `Permission`: Interface for defining individual permissions
- `RuleBuilder`: Interface for building CASL rules

### Enums

- `Action`: Available actions (Create, Read, Update, Delete, Manage)

## Error Handling

The package throws standard NestJS exceptions when authorization fails:

- `UnauthorizedException`: When the user is not authenticated
- `ForbiddenException`: When the user lacks required permissions

## Contributing

Contributions are welcome! Please read our contributing guidelines for details.

## License

[MIT License](LICENSE)

## Credits

Built with ❤️ using:
- [NestJS](https://nestjs.com/)
- [CASL](https://casl.js.org/)
- [@casl/prisma](https://github.com/stalniy/casl/tree/master/packages/casl-prisma)

---

Made with 🚀 by [Your Name/Organization]
