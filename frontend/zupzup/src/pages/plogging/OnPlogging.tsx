import styled from 'styled-components';

import { PloggingMap, OnPloggingBackground } from 'components';

const OnPlogging = () => {
  return (
    <S.Wrap>
      <OnPloggingBackground />
      <PloggingMap />
    </S.Wrap>
  );
};

export default OnPlogging;

const S = {
  Wrap: styled.div`
    position: relative;
    display: flex;
    flex-direction: column;
    width: 100%;
    height: 100vh;
    background-color: ${({ theme }) => theme.color.background};
  `,
};
