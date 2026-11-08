// TostónSync — optional build-time Google OAuth defaults.
// Defaults are intentionally empty. Configure automatic PS5 Drive in Settings.
// The public-package security gate rejects embedded client credentials; keep
// public builds empty here. Never embed access tokens, refresh tokens or any
// user's account credentials. Browser Drive and daemon Drive are separate.

#ifndef TOSTONSYNC_GDRIVE_DEFAULT_CREDS_H
#define TOSTONSYNC_GDRIVE_DEFAULT_CREDS_H

#define GDRIVE_DEFAULT_CLIENT_ID     ""
#define GDRIVE_DEFAULT_CLIENT_SECRET ""

#endif // TOSTONSYNC_GDRIVE_DEFAULT_CREDS_H
