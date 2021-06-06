import React from 'react';
import {RoomManage} from './RoomManage';
import {useRoom} from './useRoom';
import {Room} from './Room';
import {useConfig} from './useConfig';
import {url} from "./url";

export const Router = () => {
    const {room, state, ...other} = useRoom();
    const config = useConfig();

    if(window.location.pathname === "/oauth"){
        config.oauth().then(() => {
            window.location.href = url
        })
            .catch(() =>{
                window.location.href = url
            });
    }

    if (config.loading) {
        // show spinner
        return null;
    }

    if (state) {
        return <Room state={state} {...other} />;
    }

    return <RoomManage room={room} config={config} />;
};
