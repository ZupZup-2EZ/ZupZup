import styled from 'styled-components';

import ClockSvg from 'assets/icons/clock.svg?react';
import PathSvg from 'assets/icons/path.svg?react';
import DumbbellSvg from 'assets/icons/dumbbell.svg?react';

const RecordBox = () => {
  return (
    <S.Wrap>
      <S.Header>2023.10.18 14:23</S.Header>
      <S.PloggingRecords>
        <S.RecordInfoBox>
          <PathSvg />
          <S.RecordInfo>2.4km</S.RecordInfo>
        </S.RecordInfoBox>
        <S.RecordInfoBox>
          <ClockSvg />
          <S.RecordInfo>2시간 11분</S.RecordInfo>
        </S.RecordInfoBox>
        <S.RecordInfoBox>
          <DumbbellSvg />
          <S.RecordInfo>230Kcal</S.RecordInfo>
        </S.RecordInfoBox>
      </S.PloggingRecords>
    </S.Wrap>
  );
};

export default RecordBox;

const S = {
  Wrap: styled.div`
    display: flex;
    flex-direction: column;
    width: 100%;
    height: 100px;
    background-color: ${({ theme }) => theme.color.white};
    border-radius: 8px;
    box-shadow: 0px 2px 2px 0px rgba(0, 0, 0, 0.04);
    padding: 14px 16px;
    margin: 0 0 20px 0;
  `,
  Header: styled.div`
    color: ${({ theme }) => theme.color.gray3};
    font-size: ${({ theme }) => theme.font.size.body3};
    font-family: ${({ theme }) => theme.font.family.body3};
    line-height: ${({ theme }) => theme.font.lineheight.body3};
  `,
  PloggingRecords: styled.div`
    display: flex;
    align-items: center;
    justify-content: space-between;
    width: 100%;
    height: 100%;
  `,
  RecordInfoBox: styled.div`
    display: flex;

    & > svg {
      width: 16px;
      height: 16px;
      margin: 0 10px 0 0;
    }
  `,
  RecordInfo: styled.div`
    font-size: ${({ theme }) => theme.font.size.focus3};
    font-family: ${({ theme }) => theme.font.family.focus3};
    line-height: ${({ theme }) => theme.font.lineheight.focus3};
    white-space: nowrap;
  `,
};
