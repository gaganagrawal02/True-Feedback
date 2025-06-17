import { NextAuthOptions, User as NextAuthUser } from 'next-auth';
import CredentialsProvider from 'next-auth/providers/credentials';
import bcrypt from 'bcryptjs';
import dbConnect from '@/lib/dbConnect';
import UserModel from '@/model/User';
import { JWT } from 'next-auth/jwt';
import { AdapterUser } from 'next-auth/adapters';

interface ExtendedUser extends AdapterUser {
  _id: string;
  username: string;
  isVerified: boolean;
  isAcceptingMessages: boolean;
  email: string;
  password: string;
}

export const authOptions: NextAuthOptions = {
  providers: [
    CredentialsProvider({
      id: 'credentials',
      name: 'Credentials',
      credentials: {
        email: { label: 'Email', type: 'text' },
        password: { label: 'Password', type: 'password' },
      },
      async authorize(credentials): Promise<ExtendedUser | null> {
        await dbConnect();

        if (!credentials?.email || !credentials.password) {
          throw new Error('Email and password are required');
        }

        const user = await UserModel.findOne({
          $or: [
            { email: credentials.email },
            { username: credentials.email },
          ],
        });

        if (!user) {
          throw new Error('No user found with this email or username');
        }

        if (!user.isVerified) {
          throw new Error('Please verify your account before logging in');
        }

        const isPasswordCorrect = await bcrypt.compare(
          credentials.password,
          user.password
        );

        if (!isPasswordCorrect) {
          throw new Error('Incorrect password');
        }

        return {
          _id: user._id.toString(),
          username: user.username,
          isVerified: user.isVerified,
          isAcceptingMessages: user.isAcceptingMessages,
          email: user.email,
          password: user.password,
        };
      },
    }),
  ],
  callbacks: {
    async jwt({ token, user }: { token: JWT; user?: ExtendedUser }) {
      if (user) {
        token._id = user._id;
        token.isVerified = user.isVerified;
        token.isAcceptingMessages = user.isAcceptingMessages;
        token.username = user.username;
      }
      return token;
    },
    async session({ session, token }) {
      if (session.user && token) {
        (session.user as any)._id = token._id;
        (session.user as any).isVerified = token.isVerified;
        (session.user as any).isAcceptingMessages = token.isAcceptingMessages;
        (session.user as any).username = token.username;
      }
      return session;
    },
  },
  session: {
    strategy: 'jwt',
  },
  secret: process.env.NEXTAUTH_SECRET,
  pages: {
    signIn: '/sign-in',
  },
};
