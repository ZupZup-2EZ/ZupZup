import { useRef, useEffect } from 'react';
import styled from 'styled-components';

const Camera = () => {
  const cameraRef = useRef<HTMLVideoElement>(null);

  useEffect(() => {
    const enableCamera = async () => {
      try {
        const stream = await navigator.mediaDevices.getUserMedia({
          video: true,
        });
        if (cameraRef.current) {
          cameraRef.current!.srcObject = stream;
        }
      } catch (error) {
        console.log('camera access error : ', error);
      }
    };

    enableCamera();

    return () => {
      if (cameraRef.current) {
        const stream = cameraRef.current!.srcObject as MediaStream;
        if (stream) {
          const tracks = stream.getTracks();
          tracks.forEach(track => {
            track.stop();
          });
        }
      }
    };
  }, []);

  return (
    <S.Wrap>
      <S.CameraBox ref={cameraRef} />
    </S.Wrap>
  );
};

export default Camera;

const S = {
  Wrap: styled.div`
    position: relative;
    display: flex;
    flex-direction: column;
    width: 100%;
    height: 100vh;
    background-color: ${({ theme }) => theme.color.background};
  `,
  CameraBox: styled.video`
    width: 100%;
    height: 100%;
  `,
};
