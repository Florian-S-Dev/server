import React from 'react';
import {
    Box,
    Button,
    Checkbox,
    CircularProgress,
    FormControl,
    FormControlLabel,
    Grid,
    Link,
    Paper,
    TextField,
    Typography,
} from '@material-ui/core';
import {FCreateRoom, UseRoom} from './useRoom';
import {RoomMode, UIConfig} from './message';
import {randomRoomName} from './name';
import {getRoomFromURL} from './useRoomID';
import logo from './logo.svg';
import {UseConfig} from './useConfig';
import {LoginForm} from './LoginForm';

const defaultMode = (authMode: UIConfig['authMode'], loggedIn: boolean): RoomMode => {
    if (loggedIn) {
        return RoomMode.Turn;
    }
    switch (authMode) {
        case 'all':
            return RoomMode.Turn;
        case 'turn':
            return RoomMode.Stun;
        case 'none':
        default:
            return RoomMode.Turn;
    }
};

const CreateRoom = ({room, config}: Pick<UseRoom, 'room'> & {config: UIConfig}) => {
    const [id, setId] = React.useState(
        () => getRoomFromURL(window.location.search) ?? randomRoomName()
    );
    const mode = defaultMode(config.authMode, config.loggedIn);
    const [ownerLeave, setOwnerLeave] = React.useState(config.closeRoomWhenOwnerLeaves);
    const submit = () =>
        room({
            type: 'create',
            payload: {
                mode,
                closeOnOwnerLeave: ownerLeave,
                id: id || undefined,
            },
        });
    return (
        <div>
            <FormControl fullWidth>
                <TextField
                    fullWidth
                    value={id}
                    onChange={(e) => setId(e.target.value)}
                    label="id"
                    margin="dense"
                />
                <FormControlLabel
                    control={
                        <Checkbox
                            checked={ownerLeave}
                            onChange={(_, checked) => setOwnerLeave(checked)}
                        />
                    }
                    label="Close Room after you leave"
                />
                <Box paddingBottom={0.5}>
                    <Typography>
                        Nat Traversal via:{' '}
                        <Link
                            href="https://screego.net/#/nat-traversal"
                            target="_blank"
                            rel="noreferrer">
                            {mode.toUpperCase()}
                        </Link>
                    </Typography>
                </Box>
                <Button onClick={submit} fullWidth variant="contained">
                    Create Room
                </Button>
            </FormControl>
        </div>
    );
};

export const RoomManage = ({room, config}: {room: FCreateRoom; config: UseConfig}) => {
    const [showLogin, setShowLogin] = React.useState(false);
    const [oauthLoading, setOauthLoading] = React.useState(false);

    const canCreateRoom = config.authMode !== 'all';
    const loginVisible = !config.loggedIn && (showLogin || !canCreateRoom);

    if (!oauthLoading && window.location.pathname === '/oauth') {
        setOauthLoading(true);
        config.oauth().finally(() => setOauthLoading(false));
    }

    return (
        <Grid
            container={true}
            justify="center"
            style={{paddingTop: 50, maxWidth: 400, width: '100%', margin: '0 auto'}}
            spacing={4}>
            <Grid item xs={12}>
                <Typography align="center" gutterBottom>
                    <img src={logo} style={{width: 230}} alt="logo" />
                </Typography>
                <Paper elevation={3} style={{padding: 20}}>
                    {oauthLoading ? (
                        <div style={{display: 'flex', justifyContent: 'center'}}>
                            <CircularProgress />
                        </div>
                    ) : (
                        <>
                            {loginVisible ? (
                                <LoginForm
                                    config={config}
                                    hide={canCreateRoom ? () => setShowLogin(false) : undefined}
                                />
                            ) : (
                                <>
                                    {config.showOauth || config.showLogin ? (
                                        <Typography style={{display: 'flex', alignItems: 'center'}}>
                                            <span style={{flex: 1}}>Hello {config.user}!</span>{' '}
                                            {config.loggedIn ? (
                                                <Button
                                                    variant="outlined"
                                                    size="small"
                                                    onClick={config.logout}>
                                                    Logout
                                                </Button>
                                            ) : (
                                                <Button
                                                    variant="outlined"
                                                    size="small"
                                                    onClick={() => setShowLogin(true)}>
                                                    Login
                                                </Button>
                                            )}
                                        </Typography>
                                    ) : undefined}
                                    <CreateRoom room={room} config={config} />
                                </>
                            )}
                        </>
                    )}
                </Paper>
            </Grid>
            <div style={{position: 'absolute', margin: '0 auto', bottom: 0}}>
                Screego {config.version} |{' '}
                <Link href="https://github.com/screego/server/">GitHub</Link>
            </div>
        </Grid>
    );
};
