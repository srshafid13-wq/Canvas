/* =========================================================
   CANVAS - SCRIPT.JS
   GO LIVE MEDIA COMPATIBILITY
   Backend: https://canvas-kh9p.onrender.com
========================================================= */

const BACKEND_URL =
    "https://canvas-kh9p.onrender.com";

/* =========================================================
   STATE
========================================================= */

let stream = null;
let isStreaming = false;
let streamId = null;

let cameraEnabled = false;
let microphoneEnabled = false;

let currentFacingMode = "user";

/* =========================================================
   ELEMENTS
========================================================= */

const cameraPreview =
    document.getElementById("cameraPreview");

const cameraBtn =
    document.getElementById("cameraBtn");

const micBtn =
    document.getElementById("micBtn");

const switchCameraBtn =
    document.getElementById("switchCameraBtn");

const startStreamingBtn =
    document.getElementById("startStreamingBtn");

const endStreamingBtn =
    document.getElementById("endStreamingBtn");

const cameraMessage =
    document.getElementById("cameraMessage");

/* =========================================================
   AUTH
========================================================= */

function getAuthToken(){

    return (
        localStorage.getItem("canvasAuthToken") ||
        localStorage.getItem("authToken") ||
        localStorage.getItem("token") ||
        ""
    );

}

function authHeaders(){

    const token =
        getAuthToken();

    const headers = {
        "Content-Type":"application/json"
    };

    if(token){

        headers.Authorization =
            "Bearer " + token;

    }

    return headers;

}

/* =========================================================
   CAMERA BUTTON
========================================================= */

function updateCameraButton(){

    if(!cameraBtn){
        return;
    }

    if(cameraEnabled){

        cameraBtn.textContent =
            "Camera";

        cameraBtn.classList.add("active");

    }else{

        cameraBtn.textContent =
            "Camera Off";

        cameraBtn.classList.remove("active");

    }

}

/* =========================================================
   MICROPHONE BUTTON
========================================================= */

function updateMicButton(){

    if(!micBtn){
        return;
    }

    if(microphoneEnabled){

        micBtn.textContent =
            "Microphone";

        micBtn.classList.add("active");

    }else{

        micBtn.textContent =
            "Microphone Off";

        micBtn.classList.remove("active");

    }

}

/* =========================================================
   PREVIEW
========================================================= */

function updatePreview(){

    if(!cameraPreview){
        return;
    }

    const videoTrack =
        stream
            ? stream.getVideoTracks()[0]
            : null;

    if(
        videoTrack &&
        videoTrack.enabled
    ){

        cameraPreview.srcObject =
            stream;

        cameraPreview.style.display =
            "block";

        if(cameraMessage){

            cameraMessage.style.display =
                "none";

        }

    }else{

        cameraPreview.style.display =
            "none";

        if(cameraMessage){

            cameraMessage.style.display =
                "flex";

        }

    }

}

/* =========================================================
   START CAMERA + MICROPHONE
========================================================= */

async function startMedia(){

    if(stream){

        cameraEnabled =
            stream
                .getVideoTracks()
                .some(
                    track => track.enabled
                );

        microphoneEnabled =
            stream
                .getAudioTracks()
                .some(
                    track => track.enabled
                );

        updateCameraButton();
        updateMicButton();
        updatePreview();

        return stream;

    }

    if(
        !navigator.mediaDevices ||
        !navigator.mediaDevices.getUserMedia
    ){

        console.error(
            "getUserMedia is not supported."
        );

        return null;

    }

    try{

        const constraints = {

            video:{

                width:{
                    ideal:1920,
                    min:1280
                },

                height:{
                    ideal:1080,
                    min:720
                },

                frameRate:{
                    ideal:30,
                    max:60
                },

                facingMode:
                    currentFacingMode

            },

            audio:{

                echoCancellation:true,

                noiseSuppression:true,

                autoGainControl:true,

                channelCount:2,

                sampleRate:48000,

                sampleSize:16

            }

        };

        stream =
            await navigator
                .mediaDevices
                .getUserMedia(
                    constraints
                );

        const videoTracks =
            stream.getVideoTracks();

        const audioTracks =
            stream.getAudioTracks();

        cameraEnabled =
            videoTracks.length > 0;

        microphoneEnabled =
            audioTracks.length > 0;

        videoTracks.forEach(
            track => {

                track.enabled =
                    true;

            }
        );

        audioTracks.forEach(
            track => {

                track.enabled =
                    true;

            }
        );

        if(cameraPreview){

            cameraPreview.srcObject =
                stream;

            cameraPreview.muted = true;

            cameraPreview.playsInline = true;

            await cameraPreview
                .play()
                .catch(
                    () => {}
                );

        }

        updateCameraButton();
        updateMicButton();
        updatePreview();

        return stream;

    }catch(error){

        console.error(
            "Camera/microphone error:",
            error
        );

        stream = null;

        cameraEnabled = false;

        microphoneEnabled = false;

        updateCameraButton();
        updateMicButton();
        updatePreview();

        return null;

    }

}

/* =========================================================
   STOP CAMERA + MICROPHONE
========================================================= */

function stopMedia(){

    if(stream){

        stream
            .getTracks()
            .forEach(
                track => {

                    try{
                        track.stop();
                    }catch(error){}

                }
            );

    }

    stream = null;

    cameraEnabled = false;

    microphoneEnabled = false;

    if(cameraPreview){

        cameraPreview.srcObject =
            null;

        cameraPreview.style.display =
            "none";

    }

    updateCameraButton();
    updateMicButton();
    updatePreview();

}

/* =========================================================
   CAMERA BUTTON
========================================================= */

if(cameraBtn){

    cameraBtn.addEventListener(
        "click",
        async function(){

            if(!stream){

                await startMedia();

                return;

            }

            const videoTrack =
                stream
                    .getVideoTracks()[0];

            if(!videoTrack){

                await startMedia();

                return;

            }

            videoTrack.enabled =
                !videoTrack.enabled;

            cameraEnabled =
                videoTrack.enabled;

            updateCameraButton();
            updatePreview();

        }
    );

}

/* =========================================================
   MICROPHONE BUTTON
========================================================= */

if(micBtn){

    micBtn.addEventListener(
        "click",
        async function(){

            if(!stream){

                await startMedia();

                return;

            }

            const audioTrack =
                stream
                    .getAudioTracks()[0];

            if(!audioTrack){

                return;

            }

            audioTrack.enabled =
                !audioTrack.enabled;

            microphoneEnabled =
                audioTrack.enabled;

            updateMicButton();

        }
    );

}

/* =========================================================
   SWITCH CAMERA
========================================================= */

if(switchCameraBtn){

    switchCameraBtn.addEventListener(
        "click",
        async function(){

            if(isStreaming){

                return;

            }

            currentFacingMode =
                currentFacingMode === "user"
                    ? "environment"
                    : "user";

            const oldStream =
                stream;

            try{

                const newStream =
                    await navigator
                        .mediaDevices
                        .getUserMedia({

                            video:{

                                width:{
                                    ideal:1920,
                                    min:1280
                                },

                                height:{
                                    ideal:1080,
                                    min:720
                                },

                                frameRate:{
                                    ideal:30,
                                    max:60
                                },

                                facingMode:
                                    currentFacingMode

                            },

                            audio:false

                        });

                const newVideoTrack =
                    newStream
                        .getVideoTracks()[0];

                if(!newVideoTrack){

                    throw new Error(
                        "Camera unavailable"
                    );

                }

                if(oldStream){

                    const oldVideoTrack =
                        oldStream
                            .getVideoTracks()[0];

                    if(oldVideoTrack){

                        oldStream.removeTrack(
                            oldVideoTrack
                        );

                        oldVideoTrack.stop();

                    }

                    oldStream.addTrack(
                        newVideoTrack
                    );

                }else{

                    stream =
                        new MediaStream([
                            newVideoTrack
                        ]);

                }

                cameraEnabled = true;

                if(cameraPreview){

                    cameraPreview.srcObject =
                        stream;

                }

                updateCameraButton();
                updatePreview();

            }catch(error){

                console.error(
                    "Camera switch error:",
                    error
                );

                currentFacingMode =
                    currentFacingMode === "user"
                        ? "environment"
                        : "user";

            }

        }
    );

}

/* =========================================================
   START STREAMING
========================================================= */

async function startStreaming(){

    if(isStreaming){
        return;
    }

    const token =
        getAuthToken();

    if(!token){

        console.log(
            "User is not logged in."
        );

        return;

    }

    try{

        if(!stream){

            const media =
                await startMedia();

            if(!media){
                return;
            }

        }

        if(
            !stream ||
            !stream.getTracks().length
        ){

            return;

        }

        if(startStreamingBtn){

            startStreamingBtn.disabled =
                true;

        }

        const response =
            await fetch(
                BACKEND_URL +
                "/api/streams/start",
                {
                    method:"POST",
                    headers:authHeaders(),

                    body:JSON.stringify({

                        title:
                            "Canvas Live Stream"

                    })

                }
            );

        const data =
            await response
                .json()
                .catch(
                    () => ({})
                );

        if(!response.ok){

            throw new Error(
                data.message ||
                data.error ||
                "Unable to start stream."
            );

        }

        streamId =
            data.streamId ||
            data.id ||
            (
                data.stream &&
                (
                    data.stream.streamId ||
                    data.stream.id
                )
            );

        if(!streamId){

            throw new Error(
                "Stream ID was not returned."
            );

        }

        isStreaming = true;

        if(startStreamingBtn){

            startStreamingBtn.style.display =
                "none";

        }

        if(endStreamingBtn){

            endStreamingBtn.style.display =
                "block";

        }

        console.log(
            "Canvas stream started:",
            streamId
        );

    }catch(error){

        console.error(
            "Start streaming error:",
            error
        );

        isStreaming = false;

        streamId = null;

    }finally{

        if(startStreamingBtn){

            startStreamingBtn.disabled =
                false;

        }

    }

}

/* =========================================================
   STOP STREAMING
========================================================= */

async function stopStreaming(){

    if(!isStreaming){
        return;
    }

    if(!streamId){
        return;
    }

    const endingStreamId =
        streamId;

    try{

        if(endStreamingBtn){

            endStreamingBtn.disabled =
                true;

        }

        const response =
            await fetch(
                BACKEND_URL +
                "/api/streams/stop",
                {
                    method:"POST",
                    headers:authHeaders(),

                    body:JSON.stringify({

                        streamId:
                            endingStreamId

                    })

                }
            );

        const data =
            await response
                .json()
                .catch(
                    () => ({})
                );

        if(!response.ok){

            throw new Error(
                data.message ||
                data.error ||
                "Unable to stop stream."
            );

        }

        isStreaming = false;

        streamId = null;

        stopMedia();

        if(startStreamingBtn){

            startStreamingBtn.style.display =
                "block";

        }

        if(endStreamingBtn){

            endStreamingBtn.style.display =
                "none";

        }

        console.log(
            "Canvas stream ended."
        );

    }catch(error){

        console.error(
            "Stop streaming error:",
            error
        );

    }finally{

        if(endStreamingBtn){

            endStreamingBtn.disabled =
                false;

        }

    }

}

/* =========================================================
   BUTTON COMPATIBILITY
========================================================= */

if(startStreamingBtn){

    startStreamingBtn.addEventListener(
        "click",
        startStreaming
    );

}

if(endStreamingBtn){

    endStreamingBtn.addEventListener(
        "click",
        stopStreaming
    );

}

/* =========================================================
   INITIAL UI
========================================================= */

updateCameraButton();

updateMicButton();

updatePreview();

/*
   Do NOT automatically end a live stream
   when the page is closed or navigated away.

   Only the explicit End Streaming button
   should end the server-side stream.
*/

/* =========================================================
   PAGE LOAD
========================================================= */

document.addEventListener(
    "DOMContentLoaded",
    function(){

        updateCameraButton();

        updateMicButton();

        updatePreview();

    }
);
