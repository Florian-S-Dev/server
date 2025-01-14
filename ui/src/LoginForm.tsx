import {UseConfig} from './useConfig';
import React from 'react';
import {
    Button,
    ButtonProps,
    CircularProgress,
    Divider,
    FormControl,
    TextField,
    Typography,
} from '@material-ui/core';
import {makeStyles} from '@material-ui/core/styles';
import {green} from '@material-ui/core/colors';

export const LoginForm = ({
    config: {login, loginoauth, showLogin, showOauth},
    hide,
}: {
    config: UseConfig;
    hide?: () => void;
}) => {
    const [user, setUser] = React.useState('');
    const [pass, setPass] = React.useState('');
    const [loading, setLoading] = React.useState(false);
    const oauthLogin = () => {
        loginoauth().then((url) => (window.location.href = url));
    };

    const submit = async (event: {preventDefault: () => void}) => {
        event.preventDefault();
        setLoading(true);
        login(user, pass)
            .then(() => {
                setLoading(false);
            })
            .catch(() => setLoading(false));
    };
    return (
        <div>
            <FormControl fullWidth>
                <form onSubmit={submit}>
                    <div style={{display: 'flex', alignItems: 'center'}}>
                        <Typography style={{flex: 1}}>Login to Screego</Typography>
                        {hide ? (
                            <Button variant="outlined" size="small" onClick={hide}>
                                Go Back
                            </Button>
                        ) : undefined}
                    </div>
                    {showLogin ? (
                        <>
                            <TextField
                                fullWidth
                                value={user}
                                onChange={(e) => setUser(e.target.value)}
                                label="Username"
                                margin="dense"
                            />
                            <TextField
                                fullWidth
                                value={pass}
                                type="password"
                                onChange={(e) => setPass(e.target.value)}
                                label="Password"
                                margin="dense"
                            />
                            <LoadingButton
                                style={{marginTop: 5}}
                                type="submit"
                                loading={loading}
                                onClick={submit}
                                fullWidth
                                variant="contained">
                                Login
                            </LoadingButton>
                        </>
                    ) : undefined}
                    {showLogin && showOauth ? (
                        <Divider style={{marginTop: 8, marginBottom: 3}} />
                    ) : undefined}
                    {showOauth ? (
                        <Button
                            style={{marginTop: 5}}
                            onClick={oauthLogin}
                            fullWidth
                            variant="outlined">
                            oAuth
                        </Button>
                    ) : undefined}
                </form>
            </FormControl>
        </div>
    );
};

export const LoadingButton = ({loading, children, ...props}: ButtonProps & {loading: boolean}) => {
    const classes = useStyles();
    return (
        <Button {...props} disabled={loading}>
            {children}
            {loading && (
                <CircularProgress className={classes.buttonProgress} size={24} color="secondary" />
            )}
        </Button>
    );
};

const useStyles = makeStyles(() => ({
    buttonProgress: {
        color: green[500],
        position: 'absolute',
        top: '50%',
        left: '50%',
        marginTop: -12,
        marginLeft: -12,
    },
}));
