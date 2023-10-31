import { useRef, useState, useEffect } from 'react';
import styled from 'styled-components';

import { CaptureResult } from 'components';

import XSvg from 'assets/icons/x.svg?react';

interface Props {
  setCameraOn: (cameraOn: boolean) => void;
}

const Camera = ({ setCameraOn }: Props) => {
  const cameraRef = useRef<HTMLVideoElement>(null);
  const [capture, setCapture] = useState<boolean>(false);

  useEffect(() => {
    const enableCamera = async () => {
      try {
        const stream = await navigator.mediaDevices.getUserMedia({
          video: {
            facingMode: 'environment',
          },
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
      {capture && (
        <CaptureResult cameraRef={cameraRef} setCapture={setCapture} />
      )}
      <S.Header>
        <S.CancelButton onClick={() => setCameraOn(false)}>
          <XSvg />
        </S.CancelButton>
      </S.Header>
      <S.CameraBox ref={cameraRef} autoPlay playsInline height="100%" />
      <S.UserAccess>
        <S.CaptureButton onClick={() => setCapture(true)}></S.CaptureButton>
      </S.UserAccess>
    </S.Wrap>
  );
};

export default Camera;

const S = {
  Wrap: styled.div`
    position: absolute;
    display: flex;
    flex-direction: column;
    top: 0;
    left: 0;
    width: 100%;
    height: 100vh;
    background-color: ${({ theme }) => theme.color.background};
    z-index: 400;
  `,
  Header: styled.div`
    width: 100%;
    height: 100px;
    display: flex;
    justify-content: flex-end;
    align-items: center;
    padding: 0 15px;
  `,
  CancelButton: styled.button`
    background-color: transparent;
    font-size: ${({ theme }) => theme.font.size.focus3};
    font-family: ${({ theme }) => theme.font.family.focus3};
    line-height: ${({ theme }) => theme.font.lineheight.focus3};
    & > svg {
      width: 20px;
      height: 20px;
    }
  `,
  CameraBox: styled.video`
    flex-grow: 1;
    width: 100%;
    object-fit: cover;
  `,
  UserAccess: styled.div`
    display: flex;
    justify-content: center;
    align-items: center;
    width: 100%;
    height: 200px;
    padding: 20px 0;
  `,
  CaptureButton: styled.button`
    width: 50px;
    height: 50px;
    border-radius: 25px;
    background-color: ${({ theme }) => theme.color.white};
    border: 4px solid ${({ theme }) => theme.color.gray5};
    box-shadow: 0px 0px 10px 1px #3333;

    &:hover {
      box-shadow: 0px 0px 4px 1px #3333;
    }
  `,
};