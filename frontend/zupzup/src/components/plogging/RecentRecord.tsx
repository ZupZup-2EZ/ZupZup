import styled from 'styled-components';

import SmallClockSvg from 'assets/icons/smallclock.svg?react';

const RecentRecord = () => {
  return (
    <S.Wrap>
      <S.RecordBox>
        <SmallClockSvg />
        <S.RecordInfo>4일 전</S.RecordInfo>&nbsp;|&nbsp;
        <S.RecordInfo>132 km</S.RecordInfo>
      </S.RecordBox>
    </S.Wrap>
  );
};

export default RecentRecord;

const S = {
  Wrap: styled.div`
    display: flex;
    align-items: center;
    justify-content: flex-end;
    width: 100%;
    height: 45px;
    padding: 0 16px;
  `,
  RecordBox: styled.div`
    display: flex;
    align-items: center;
    color: ${({ theme }) => theme.color.gray2};
    font-size: ${({ theme }) => theme.font.size.focus3};
    font-family: ${({ theme }) => theme.font.family.focus3};
    line-height: ${({ theme }) => theme.font.lineheight.focus3};

    & > svg {
      margin: 0 5px 0 0;
    }
  `,
  RecordInfo: styled.div`
    font-size: ${({ theme }) => theme.font.size.focus3};
    font-family: ${({ theme }) => theme.font.family.focus3};
    line-height: ${({ theme }) => theme.font.lineheight.focus3};
  `,
};
