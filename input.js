const cameraPreview =
    document.getElementById("cameraPreview");

const cameraMessage =
    document.getElementById("cameraMessage");

const cameraButton =
    document.getElementById("cameraButton");

const micButton =
    document.getElementById("micButton");

const permissionMessage =
    document.getElementById("permissionMessage");

const startStreaming =
    document.getElementById("startStreaming");


let mediaStream = null;
let cameraEnabled = false;
let micEnabled = false;


/* START CAMERA + MICROPHONE */

async function startCamera() {

    try {

        mediaStream =
            await navigator.mediaDevices.getUserMedia({
                video: true,
                audio: true
            });

        cameraPreview.srcObject =
            mediaStream;

        cameraPreview.style.display =
            "block";

        cameraMessage.style.display =
            "none";

        cameraEnabled = true;
        micEnabled = true;

        cameraButton.classList.add("active");
        micButton.classList.add("active");

        permissionMessage.textContent =
            "Camera and microphone are ready.";

    }

    catch (error) {

        console.error(error);

        permissionMessage.textContent =
            "Camera/microphone permission was denied or unavailable.";

    }

}


/* CAMERA BUTTON */

cameraButton.addEventListener(
    "click",
    async function () {

        if (!mediaStream) {

            await startCamera();

            return;
        }


        const videoTracks =
            mediaStream.getVideoTracks();

        if (videoTracks.length === 0) return;

        cameraEnabled =
            !cameraEnabled;

        videoTracks[0].enabled =
            cameraEnabled;

        cameraButton.classList.toggle(
            "active",
            cameraEnabled
        );

    }
);


/* MICROPHONE BUTTON */

micButton.addEventListener(
    "click",
    async function () {

        if (!mediaStream) {

            await startCamera();

            return;
        }


        const audioTracks =
            mediaStream.getAudioTracks();

        if (audioTracks.length === 0) return;

        micEnabled =
            !micEnabled;

        audioTracks[0].enabled =
            micEnabled;

        micButton.classList.toggle(
            "active",
            micEnabled
        );

    }
);


/* START STREAM */

startStreaming.addEventListener(
    "click",
    function () {

        const title =
            document.getElementById(
                "streamTitle"
            ).value.trim();


        if (!mediaStream) {

            alert(
                "Please turn on your camera and microphone first."
            );

            return;
        }


        if (!title) {

            alert(
                "Please enter a stream title."
            );

            return;
        }


        localStorage.setItem(
            "canvasStreamTitle",
            title
        );

        localStorage.setItem(
            "canvasStreamCategory",
            document.getElementById(
                "category"
            ).value
        );


        alert(
            "Your camera is ready! The streaming backend still needs to be connected."
        );

    }
);


/* TRY TO START CAMERA WHEN PAGE LOADS */

window.addEventListener(
    "load",
    function () {

        startCamera();

    }
);
