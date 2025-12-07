/* eslint-disable */
import {
  Body,
  Controller,
  Post,
  Get,
  Req,
  UseGuards,
  Query,
  Res,
} from '@nestjs/common';
import { AuthService } from './auth.service';
import { JwtAuthGuard } from './guards/jwt-auth.guard';
import { ConfigService } from '@nestjs/config';
import type { Response } from 'express';

@Controller('auth')
export class AuthController {
  constructor(
    private authService: AuthService,
    private config: ConfigService,
  ) {}

  @Post('signup')
  signup(@Body() dto: any) {
    return this.authService.signup(dto);
  }

  @Post('login')
  login(@Body() dto: any) {
    return this.authService.login(dto);
  }

  @Post('google-complete-signup')
  googleCompleteSignup(@Body() dto: any) {
    return this.authService.googleCompleteSignup(dto);
  }

  @UseGuards(JwtAuthGuard)
  @Get('profile')
  getProfile(@Req() req) {
    return this.authService.getProfile(req.user.id);
  }

  @Post('refresh')
  refresh(@Body('refreshToken') token: string) {
    return this.authService.refresh(token);
  }

  @Get('google')
  googleAuth(@Res() res: Response) {
    const clientId = this.config.get<string>('GOOGLE_CLIENT_ID')!;
    const redirectUri = this.config.get<string>('GOOGLE_REDIRECT_URI')!;
    const scope =
      'https://www.googleapis.com/auth/userinfo.email https://www.googleapis.com/auth/userinfo.profile';

    const url = `https://accounts.google.com/o/oauth2/v2/auth?client_id=${clientId}&redirect_uri=${encodeURIComponent(
      redirectUri,
    )}&response_type=code&scope=${encodeURIComponent(scope)}`;

    return res.redirect(url);
  }

  @Get('google/redirect')
  async googleRedirect(@Query('code') code: string, @Res() res: Response) {
    const result = await this.authService.googleLogin(code);

    const frontend = this.config.get<string>('FRONTEND_URL')!;
    const isNew = result.isNewUser ? 'true' : 'false';

    const email = encodeURIComponent(result.user.email);
    const name = encodeURIComponent(result.user.name || '');
    const providerId = encodeURIComponent(result.user.providerId || '');

    const accessToken = result.tokens
      ? encodeURIComponent(result.tokens.accessToken)
      : '';
    const refreshToken = result.tokens
      ? encodeURIComponent(result.tokens.refreshToken)
      : '';

    return res.redirect(
      `${frontend}/google-callback?isNewUser=${isNew}&email=${email}&name=${name}&providerId=${providerId}&accessToken=${accessToken}&refreshToken=${refreshToken}`,
    );
  }
}
