import {UIConfig} from './message';
import {useSnackbar} from 'notistack';
import React from 'react';

export interface UseConfig extends UIConfig {
    login: (username: string, password: string) => Promise<void>;
    refetch: () => void;
    logout: () => Promise<void>;
    loading: boolean;
    oauth: () => Promise<void>;
    loginoauth: () => Promise<string>;
}

export const useConfig = (): UseConfig => {
    const {enqueueSnackbar} = useSnackbar();
    const [{loading, ...config}, setConfig] = React.useState<UIConfig & {loading: boolean}>({
        authMode: 'all',
        user: 'guest',
        loggedIn: false,
        loading: true,
        version: 'unknown',
        closeRoomWhenOwnerLeaves: true,
    });

    const refetch = React.useCallback(async () => {
        return fetch(`config`)
            .then((data) => data.json())
            .then(setConfig);
    }, [setConfig]);

    const login = async (username: string, password: string) => {
        const body = new FormData();
        body.set('user', username);
        body.set('pass', password);
        const result = await fetch(`login`, {method: 'POST', body});
        const json = await result.json();
        if (result.status !== 200) {
            enqueueSnackbar('Login Failed: ' + json.message, {variant: 'error'});
        } else {
            await refetch();
            enqueueSnackbar('Logged in!', {variant: 'success'});
        }
    };

    const oauth = async () => {
        const result = await fetch(`oauth` + window.location.search, {method: 'GET'});
        window.history.replaceState(null, document.title, "/")
        const json = await result.json();
        if (result.status !== 200) {
            enqueueSnackbar('OAuth Failed: ' + json.message, {variant: 'error'});
        } else {
            await refetch();
            enqueueSnackbar('OAuth login successful!', {variant: 'success'});
        }
    };

    const loginoauth = async () => {
        const result = await fetch(`loginoauth`, {method: 'GET'});
        const json = await result.json();
        if (result.status !== 200) {
            enqueueSnackbar('OAuth Failed: ' + json.message, {variant: 'error'});
        } else {
            return json.message
        }
    };

    const logout = async () => {
        const result = await fetch(`logout`, {method: 'POST'});
        if (result.status !== 200) {
            enqueueSnackbar('Logout Failed: ' + (await result.text()), {variant: 'error'});
        } else {
            await refetch();
            enqueueSnackbar('Logged Out.', {variant: 'success'});
        }
    };

    // eslint-disable-next-line react-hooks/exhaustive-deps
    React.useEffect(() => void refetch(), []);

    return {...config, refetch, loading, login, logout, oauth, loginoauth};
};
